"""Anomaly and threat detection service.

Implements real-time heuristic security analysis:
- Impossible travel detection (Haversine formula velocity check between sequential logins)
- Sudden geographical shift detection
- Rapid successive failed login bursts (credential stuffing / brute force)
- Automated alert emission and risk-based step-up authentication recommendations
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from auth_service.core.logger import get_logger

logger = get_logger("auth_service.services.anomaly_detection")


class GeoCoordinates:
    """Latitude and longitude coordinates with helper calculation methods."""

    def __init__(self, latitude: float, longitude: float, city: Optional[str] = None, country: Optional[str] = None) -> None:
        self.latitude = latitude
        self.longitude = longitude
        self.city = city or "Unknown"
        self.country = country or "Unknown"

    def distance_to(self, other: GeoCoordinates) -> float:
        """Calculate great-circle distance in kilometers using the Haversine formula."""
        earth_radius_km = 6371.0

        lat1_rad = math.radians(self.latitude)
        lon1_rad = math.radians(self.longitude)
        lat2_rad = math.radians(other.latitude)
        lon2_rad = math.radians(other.longitude)

        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad

        a = (
            math.sin(dlat / 2.0) ** 2
            + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2.0) ** 2
        )
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return earth_radius_km * c


class AnomalyReport:
    """Represents the outcome of an anomaly evaluation."""

    def __init__(
        self,
        is_suspicious: bool,
        risk_score: int,
        anomalies: List[str],
        velocity_kmh: Optional[float] = None,
        distance_km: Optional[float] = None,
    ) -> None:
        self.is_suspicious = is_suspicious
        self.risk_score = risk_score
        self.anomalies = anomalies
        self.velocity_kmh = velocity_kmh
        self.distance_km = distance_km

    def to_dict(self) -> Dict[str, Any]:
        """Convert anomaly report to dictionary."""
        return {
            "is_suspicious": self.is_suspicious,
            "risk_score": self.risk_score,
            "anomalies": self.anomalies,
            "velocity_kmh": round(self.velocity_kmh, 2) if self.velocity_kmh else None,
            "distance_km": round(self.distance_km, 2) if self.distance_km else None,
        }


class AnomalyDetectionService:
    """Evaluates login telemetry for behavioral anomalies."""

    MAX_REASONABLE_SPEED_KMH = 850.0  # Typical commercial airliner speed limit
    MIN_DISTANCE_FOR_VELOCITY_CHECK_KM = 50.0  # Ignore small local ISP routing differences

    def evaluate_travel_velocity(
        self,
        last_coords: Optional[GeoCoordinates],
        last_timestamp: Optional[datetime],
        current_coords: Optional[GeoCoordinates],
        current_timestamp: Optional[datetime],
    ) -> Tuple[bool, Optional[float], Optional[float]]:
        """Determine if travel between two points exceeds physical possibility.

        Returns:
            Tuple of (is_impossible, distance_km, velocity_kmh)
        """
        if not last_coords or not current_coords or not last_timestamp or not current_timestamp:
            return False, None, None

        # Calculate time delta in hours
        delta_seconds = abs((current_timestamp - last_timestamp).total_seconds())
        if delta_seconds < 1.0:
            delta_seconds = 1.0  # Prevent division by zero

        delta_hours = delta_seconds / 3600.0
        distance_km = last_coords.distance_to(current_coords)

        # If locations are very close, ignore velocity check (e.g. cellular tower switching)
        if distance_km < self.MIN_DISTANCE_FOR_VELOCITY_CHECK_KM:
            return False, distance_km, (distance_km / delta_hours)

        velocity_kmh = distance_km / delta_hours
        is_impossible = velocity_kmh > self.MAX_REASONABLE_SPEED_KMH

        return is_impossible, distance_km, velocity_kmh

    def assess_login_event(
        self,
        last_coords: Optional[GeoCoordinates],
        last_timestamp: Optional[datetime],
        current_coords: Optional[GeoCoordinates],
        current_timestamp: Optional[datetime],
        is_known_device: bool,
        failed_attempts_last_hour: int = 0,
    ) -> AnomalyReport:
        """Perform comprehensive heuristic threat assessment on an authentication attempt."""
        anomalies: List[str] = []
        risk_score = 0

        # 1. Travel velocity
        is_impossible, dist, vel = self.evaluate_travel_velocity(
            last_coords, last_timestamp, current_coords, current_timestamp
        )
        if is_impossible:
            risk_score += 65
            anomalies.append(
                f"Impossible travel detected: {round(dist, 1)}km in {round(abs((current_timestamp - last_timestamp).total_seconds()) / 60, 1)}m "
                f"({round(vel, 1)} km/h)"
            )

        # 2. Country switch
        if (
            last_coords
            and current_coords
            and last_coords.country != current_coords.country
            and not is_impossible
        ):
            risk_score += 20
            anomalies.append(f"Cross-border login: {last_coords.country} -> {current_coords.country}")

        # 3. Unknown device
        if not is_known_device:
            risk_score += 15
            anomalies.append("Login from unfamiliar device")

        # 4. Recent failed attempts
        if failed_attempts_last_hour >= 5:
            risk_score += 30
            anomalies.append(f"Preceded by {failed_attempts_last_hour} failed attempts in the last hour")

        risk_score = min(risk_score, 100)
        is_suspicious = risk_score >= 50

        if is_suspicious:
            logger.warning("Suspicious login attempt detected! Risk score: %s, Anomalies: %s", risk_score, anomalies)

        return AnomalyReport(
            is_suspicious=is_suspicious,
            risk_score=risk_score,
            anomalies=anomalies,
            velocity_kmh=vel,
            distance_km=dist,
        )


# Global singleton
anomaly_detector = AnomalyDetectionService()


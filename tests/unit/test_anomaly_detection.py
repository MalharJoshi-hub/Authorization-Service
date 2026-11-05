"""Unit tests for anomaly detection and impossible travel evaluation."""

from datetime import datetime, timedelta, timezone
import pytest
from auth_service.services.anomaly_detection_service import (
    AnomalyDetectionService,
    GeoCoordinates,
    anomaly_detector,
)


def test_haversine_distance():
    # New York (40.7128, -74.0060) to London (51.5074, -0.1278)
    nyc = GeoCoordinates(40.7128, -74.0060, city="New York", country="US")
    london = GeoCoordinates(51.5074, -0.1278, city="London", country="GB")

    distance_km = nyc.distance_to(london)
    # Great-circle distance NYC to London is approx 5,570 km
    assert 5500 < distance_km < 5650


def test_impossible_travel_detected():
    service = AnomalyDetectionService()
    now = datetime.now(timezone.utc)

    # NYC at 10:00 AM
    nyc = GeoCoordinates(40.7128, -74.0060, city="New York", country="US")
    # London at 10:30 AM (impossible in 30 minutes)
    london = GeoCoordinates(51.5074, -0.1278, city="London", country="GB")

    t1 = now
    t2 = now + timedelta(minutes=30)

    is_impossible, distance, velocity = service.evaluate_travel_velocity(nyc, t1, london, t2)
    assert is_impossible is True
    assert velocity > 10000.0  # ~11,000 km/h


def test_realistic_travel_passed():
    service = AnomalyDetectionService()
    now = datetime.now(timezone.utc)

    # NYC at 10:00 AM
    nyc = GeoCoordinates(40.7128, -74.0060, city="New York", country="US")
    # London 10 hours later (realistic flight)
    london = GeoCoordinates(51.5074, -0.1278, city="London", country="GB")

    t1 = now
    t2 = now + timedelta(hours=10)

    is_impossible, distance, velocity = service.evaluate_travel_velocity(nyc, t1, london, t2)
    assert is_impossible is False
    assert 500 < velocity < 700  # Normal flight velocity


def test_assess_login_event_suspicious():
    service = AnomalyDetectionService()
    now = datetime.now(timezone.utc)
    nyc = GeoCoordinates(40.7128, -74.0060, city="New York", country="US")
    tokyo = GeoCoordinates(35.6762, 139.6503, city="Tokyo", country="JP")

    report = service.assess_login_event(
        last_coords=nyc,
        last_timestamp=now,
        current_coords=tokyo,
        current_timestamp=now + timedelta(minutes=15),
        is_known_device=False,
        failed_attempts_last_hour=6,
    )

    assert report.is_suspicious is True
    assert report.risk_score >= 80
    assert any("Impossible travel" in a for a in report.anomalies)
    assert any("failed attempts" in a for a in report.anomalies)
    d = report.to_dict()
    assert d["is_suspicious"] is True


def test_assess_login_event_benign():
    service = AnomalyDetectionService()
    now = datetime.now(timezone.utc)
    loc = GeoCoordinates(40.7128, -74.0060, city="New York", country="US")

    report = service.assess_login_event(
        last_coords=loc,
        last_timestamp=now - timedelta(hours=2),
        current_coords=loc,
        current_timestamp=now,
        is_known_device=True,
        failed_attempts_last_hour=0,
    )

    assert report.is_suspicious is False
    assert report.risk_score == 0


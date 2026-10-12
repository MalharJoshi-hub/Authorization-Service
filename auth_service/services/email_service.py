"""Email Notification & Dispatch Service (Layer 2).

Manages transactional email generation, template rendering, and delivery
for account activation, password recovery, and security alerts.
"""

from typing import Any, Dict, List, Optional
from auth_service.config import settings
from auth_service.core.logger import logger


class EmailService:
    """Manages transactional emails across verification and security events."""

    def __init__(self):
        self.sent_emails: List[Dict[str, Any]] = []

    async def send_email(
        self,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
    ) -> bool:
        """Dispatch email or record to in-memory queue for testing/dev."""
        email_record = {
            "to": to_email,
            "subject": subject,
            "text": body_text,
            "html": body_html or f"<p>{body_text}</p>",
            "from": settings.EMAIL_FROM,
        }
        self.sent_emails.append(email_record)
        logger.info(f"Dispatched transactional email to {to_email}: '{subject}'")
        return True

    def build_verification_url(self, token: str, base_url: str = "http://localhost:3000") -> str:
        """Construct client verification redirect URL."""
        return f"{base_url}/verify-email?token={token}"

    def build_reset_password_url(self, token: str, base_url: str = "http://localhost:3000") -> str:
        """Construct client password reset redirect URL."""
        return f"{base_url}/reset-password?token={token}"

    async def send_verification_email(self, to_email: str, token: str, base_url: str = "http://localhost:3000") -> bool:
        """Compose and dispatch account verification email."""
        link = f"{base_url}/verify-email?token={token}"
        subject = f"Verify your {settings.APP_NAME} account"
        text = f"Welcome! Please activate your account by clicking the following link: {link}\nThis link expires in 24 hours."
        html = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px;">
            <h2>Welcome to {settings.APP_NAME}</h2>
            <p>Thank you for registering. Please click the button below to verify your email address:</p>
            <p><a href="{link}" style="background: #2563eb; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
            <p style="font-size: 12px; color: #666;">Or paste this link in your browser: {link}</p>
        </div>
        """
        return await self.send_email(to_email, subject, text, html)

    async def send_password_reset_email(self, to_email: str, token: str, base_url: str = "http://localhost:3000") -> bool:
        """Compose and dispatch password recovery email."""
        link = f"{base_url}/reset-password?token={token}"
        subject = f"Reset your {settings.APP_NAME} password"
        text = f"You requested a password reset. Click the link below to set a new password: {link}\nThis link expires in 1 hour."
        html = f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px;">
            <h2>Password Reset Request</h2>
            <p>We received a request to reset your password. Click the button below to proceed:</p>
            <p><a href="{link}" style="background: #dc2626; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
            <p style="font-size: 12px; color: #666;">If you did not request this, please ignore this email.</p>
        </div>
        """
        return await self.send_email(to_email, subject, text, html)

    async def send_account_locked_alert(self, to_email: str, lockout_minutes: int) -> bool:
        """Alert user about account suspension due to failed login attempts."""
        subject = f"Security Alert: {settings.APP_NAME} Account Locked"
        text = f"Your account has been temporarily locked for {lockout_minutes} minutes due to multiple failed login attempts."
        return await self.send_email(to_email, subject, text)


email_service = EmailService()

"""
Alert Manager - Automated notification system for security alerts.

Sends alerts via:
- Email (SMTP)
- Slack (webhooks)
- SMS (Twilio - optional)

Supports severity-based formatting, throttling, and templating.

Phase 3 - Day 3: Response Automation
Author: Abhinav
Date: November 2025
"""

import os
import smtplib
import logging
import sqlite3
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field
import requests
from dotenv import load_dotenv


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# LOAD ENVIRONMENT VARIABLES FROM .env FILE
# ============================================================================

# Get project root directory (3 levels up from this file)
PROJECT_ROOT = Path(__file__).parent.parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

# Load .env file if it exists
if ENV_FILE.exists():
    load_dotenv(ENV_FILE)
    logger.info(f"✅ Loaded configuration from {ENV_FILE}")
else:
    logger.warning(f"⚠️  .env file not found at {ENV_FILE}")
    logger.info("   Using environment variables or defaults")


# ============================================================================
# CONFIGURATION
# ============================================================================

# Configuration — prefer Settings singleton, fall back to os.getenv
try:
    from config import settings as _settings
    SMTP_SERVER: str = _settings.SMTP_SERVER
    SMTP_PORT: int = _settings.SMTP_PORT
    SMTP_USERNAME: str = _settings.SMTP_USERNAME
    SMTP_PASSWORD: str = _settings.SMTP_PASSWORD
    SMTP_FROM: str = _settings.SMTP_FROM or _settings.SMTP_USERNAME
    SLACK_WEBHOOK_URL: str = _settings.SLACK_WEBHOOK_URL
except Exception:
    SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USERNAME)
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

# Alert throttling (max alerts per hour)
MAX_ALERTS_PER_HOUR = 20

# Database path for alert tracking
DB_PATH = Path("data/actions/alerts.db")


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class Alert:
    """Represents a security alert"""
    alert_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    message: str
    threat_details: Dict[str, Any]
    recipients: List[str]
    alert_type: str  # 'email', 'slack', 'sms'

    created_at: datetime = field(default_factory=datetime.utcnow)
    sent_at: Optional[datetime] = None
    status: str = "pending"  # pending, sent, failed
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'alert_id': self.alert_id,
            'severity': self.severity,
            'title': self.title,
            'message': self.message,
            'threat_details': json.dumps(self.threat_details),
            'recipients': ','.join(self.recipients),
            'alert_type': self.alert_type,
            'created_at': self.created_at.isoformat(),
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'status': self.status,
            'error_message': self.error_message
        }


# ============================================================================
# ALERT TEMPLATES
# ============================================================================

def get_email_template(severity: str, title: str, message: str, details: Dict[str, Any]) -> str:
    """
    Generate HTML email template.
    
    Args:
        severity: Alert severity level
        title: Alert title
        message: Alert message
        details: Threat details dictionary
        
    Returns:
        HTML string
    """
    # Severity colors
    colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#6c757d'
    }

    color = colors.get(severity, '#6c757d')

    # Format threat details
    details_html = ""
    for key, value in details.items():
        details_html += f"""
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">{key}</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{value}</td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: {color}; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
            .content {{ background-color: #f9f9f9; padding: 20px; border: 1px solid #ddd; border-radius: 0 0 5px 5px; }}
            .severity {{ font-size: 24px; font-weight: bold; }}
            .details {{ margin-top: 20px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            .footer {{ margin-top: 20px; font-size: 12px; color: #666; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="severity">🚨 {severity} ALERT</div>
                <h2>{title}</h2>
            </div>
            <div class="content">
                <p><strong>Time:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p><strong>Message:</strong> {message}</p>
                
                <div class="details">
                    <h3>Threat Details:</h3>
                    <table>
                        {details_html}
                    </table>
                </div>
                
                <p style="margin-top: 20px;">
                    <strong>Automated Response:</strong> This alert was generated by the Agentic AI Cybersecurity System. 
                    Appropriate actions have been taken automatically.
                </p>
            </div>
            <div class="footer">
                <p>Agentic AI Cybersecurity System | IIIT Allahabad</p>
                <p>This is an automated alert. Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    """

    return html


def get_slack_payload(severity: str, title: str, message: str, details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate Slack message payload.
    
    Args:
        severity: Alert severity level
        title: Alert title
        message: Alert message
        details: Threat details dictionary
        
    Returns:
        Slack webhook payload dictionary
    """
    # Severity colors for Slack
    colors = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#6c757d'
    }

    color = colors.get(severity, '#6c757d')

    # Format threat details as fields
    fields = []
    for key, value in details.items():
        fields.append({
            "title": key,
            "value": str(value),
            "short": True
        })

    payload = {
        "attachments": [
            {
                "color": color,
                "title": f"🚨 {severity} ALERT: {title}",
                "text": message,
                "fields": fields,
                "footer": "Agentic AI Cybersecurity System",
                "ts": int(datetime.utcnow().timestamp())
            }
        ]
    }

    return payload


# ============================================================================
# ALERT MANAGER
# ============================================================================

class AlertManager:
    """
    Manages security alert notifications.
    
    Handles email, Slack, and SMS alerts with throttling and templating.
    """

    def __init__(self, db_path: str = None):
        """
        Initialize alert manager.
        
        Args:
            db_path: Path to SQLite database for alert tracking
        """
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger(__name__ + ".AlertManager")

        # Check configurations
        self.email_configured = bool(SMTP_USERNAME and SMTP_PASSWORD)
        self.slack_configured = bool(SLACK_WEBHOOK_URL)

        if not self.email_configured:
            self.logger.warning(
                "⚠️  Email not configured (set SMTP_USERNAME and SMTP_PASSWORD)")
        else:
            self.logger.info(f"✅ Email configured: {SMTP_USERNAME}")

        if not self.slack_configured:
            self.logger.warning(
                "⚠️  Slack not configured (set SLACK_WEBHOOK_URL)")
        else:
            self.logger.info("✅ Slack configured")

        # Initialize database
        self._init_database()

        # Alert statistics
        self.stats = {
            'total_sent': 0,
            'email_sent': 0,
            'slack_sent': 0,
            'failed': 0
        }

        self.logger.info("✅ AlertManager initialized")

    def _init_database(self):
        """Create alerts database table"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT,
                threat_details TEXT,
                recipients TEXT,
                alert_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                sent_at TEXT,
                status TEXT DEFAULT 'pending',
                error_message TEXT
            )
        """)

        conn.commit()
        conn.close()

        self.logger.info("✅ Alerts database initialized")

    def _check_throttle(self) -> Tuple[bool, str]:
        """
        Check if alerts are being throttled.
        
        Returns:
            (can_send, reason) tuple
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Count alerts in last hour
            one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()

            cursor.execute("""
                SELECT COUNT(*) FROM alerts 
                WHERE created_at > ? AND status = 'sent'
            """, (one_hour_ago,))

            count = cursor.fetchone()[0]
            conn.close()

            if count >= MAX_ALERTS_PER_HOUR:
                return (False, f"Throttle limit reached ({count}/{MAX_ALERTS_PER_HOUR} per hour)")

            return (True, f"OK ({count}/{MAX_ALERTS_PER_HOUR} per hour)")

        except Exception as e:
            self.logger.error(f"Throttle check failed: {e}")
            return (True, "Throttle check failed, allowing")

    def send_email_alert(
        self,
        severity: str,
        title: str,
        message: str,
        recipients: List[str],
        threat_details: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Send email alert.
        
        Args:
            severity: CRITICAL, HIGH, MEDIUM, LOW
            title: Alert title
            message: Alert message
            recipients: List of email addresses
            threat_details: Dictionary with threat information
            
        Returns:
            (success, message) tuple
        """
        if not self.email_configured:
            return (False, "Email not configured")

        # Check throttle
        can_send, throttle_msg = self._check_throttle()
        if not can_send:
            self.logger.warning(f"⚠️  {throttle_msg}")
            return (False, throttle_msg)

        # Simulation mode — log what would happen, skip real SMTP
        try:
            from src.simulation.simulation_manager import is_simulation, log_simulation_action
            if is_simulation():
                sim_msg = log_simulation_action(
                    f"Would send email to {', '.join(recipients)}",
                    f"severity={severity}, title={title}"
                )
                return (True, sim_msg)
        except ImportError:
            pass

        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{severity}] {title}"
            msg['From'] = SMTP_FROM
            msg['To'] = ', '.join(recipients)

            # Generate HTML content
            html_content = get_email_template(
                severity, title, message, threat_details)

            # Attach HTML
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)

            # Send email
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)

            self.stats['email_sent'] += 1
            self.stats['total_sent'] += 1

            success_msg = f"✅ Email sent to {len(recipients)} recipients"
            self.logger.info(success_msg)

            return (True, success_msg)

        except Exception as e:
            error_msg = f"Email send failed: {str(e)}"
            self.logger.error(f"❌ {error_msg}")
            self.stats['failed'] += 1
            return (False, error_msg)

    def send_slack_alert(
        self,
        severity: str,
        title: str,
        message: str,
        threat_details: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Send Slack alert.
        
        Args:
            severity: CRITICAL, HIGH, MEDIUM, LOW
            title: Alert title
            message: Alert message
            threat_details: Dictionary with threat information
            
        Returns:
            (success, message) tuple
        """
        if not self.slack_configured:
            return (False, "Slack not configured")

        # Check throttle
        can_send, throttle_msg = self._check_throttle()
        if not can_send:
            self.logger.warning(f"⚠️  {throttle_msg}")
            return (False, throttle_msg)

        # Simulation mode — log what would happen, skip real Slack POST
        try:
            from src.simulation.simulation_manager import is_simulation, log_simulation_action
            if is_simulation():
                sim_msg = log_simulation_action(
                    f"Would send Slack alert: [{severity}] {title}",
                    "channel=webhook"
                )
                return (True, sim_msg)
        except ImportError:
            pass

        try:
            # Generate payload
            payload = get_slack_payload(
                severity, title, message, threat_details)

            # Send to webhook
            response = requests.post(
                SLACK_WEBHOOK_URL,
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                self.stats['slack_sent'] += 1
                self.stats['total_sent'] += 1

                success_msg = "✅ Slack alert sent"
                self.logger.info(success_msg)
                return (True, success_msg)
            else:
                error_msg = f"Slack API error: {response.status_code} - {response.text}"
                self.logger.error(f"❌ {error_msg}")
                self.stats['failed'] += 1
                return (False, error_msg)

        except Exception as e:
            error_msg = f"Slack send failed: {str(e)}"
            self.logger.error(f"❌ {error_msg}")
            self.stats['failed'] += 1
            return (False, error_msg)

    def send_alert(
        self,
        alert_id: str,
        severity: str,
        title: str,
        message: str,
        recipients: List[str],
        threat_details: Dict[str, Any],
        alert_type: str = "email"
    ) -> Tuple[bool, str]:
        """
        Send alert (email or Slack).
        
        Args:
            alert_id: Unique alert identifier
            severity: CRITICAL, HIGH, MEDIUM, LOW
            title: Alert title
            message: Alert message
            recipients: List of recipients (emails for email, ignored for Slack)
            threat_details: Dictionary with threat information
            alert_type: 'email' or 'slack'
            
        Returns:
            (success, message) tuple
        """
        # Create alert record
        alert = Alert(
            alert_id=alert_id,
            severity=severity,
            title=title,
            message=message,
            threat_details=threat_details,
            recipients=recipients,
            alert_type=alert_type
        )

        # Store in database
        self._store_alert(alert)

        # Send based on type
        if alert_type == "email":
            success, msg = self.send_email_alert(
                severity, title, message, recipients, threat_details
            )
        elif alert_type == "slack":
            success, msg = self.send_slack_alert(
                severity, title, message, threat_details
            )
        else:
            success, msg = (False, f"Unknown alert type: {alert_type}")

        # Update alert status
        alert.status = "sent" if success else "failed"
        alert.sent_at = datetime.utcnow() if success else None
        alert.error_message = None if success else msg

        self._update_alert_status(alert)

        return (success, msg)

    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent alerts from database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM alerts
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))

            rows = cursor.fetchall()
            conn.close()

            return [dict(row) for row in rows]

        except Exception as e:
            self.logger.error(f"Failed to get recent alerts: {e}")
            return []

    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Total alerts
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total = cursor.fetchone()[0]

            # By status
            cursor.execute(
                "SELECT status, COUNT(*) FROM alerts GROUP BY status")
            by_status = dict(cursor.fetchall())

            # By severity
            cursor.execute(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
            by_severity = dict(cursor.fetchall())

            conn.close()

            return {
                **self.stats,
                'total_in_db': total,
                'by_status': by_status,
                'by_severity': by_severity
            }

        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return self.stats

    def _store_alert(self, alert: Alert):
        """Store alert in database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            data = alert.to_dict()
            cursor.execute("""
                INSERT OR REPLACE INTO alerts (
                    alert_id, severity, title, message, threat_details,
                    recipients, alert_type, created_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data['alert_id'],
                data['severity'],
                data['title'],
                data['message'],
                data['threat_details'],
                data['recipients'],
                data['alert_type'],
                data['created_at'],
                data['status']
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to store alert: {e}")

    def _update_alert_status(self, alert: Alert):
        """Update alert status in database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE alerts SET
                    status = ?,
                    sent_at = ?,
                    error_message = ?
                WHERE alert_id = ?
            """, (
                alert.status,
                alert.sent_at.isoformat() if alert.sent_at else None,
                alert.error_message,
                alert.alert_id
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to update alert status: {e}")


# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

_alert_manager_instance = None


def get_alert_manager() -> AlertManager:
    """Get or create global alert manager instance"""
    global _alert_manager_instance

    if _alert_manager_instance is None:
        _alert_manager_instance = AlertManager()

    return _alert_manager_instance


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    print("Testing Alert Manager...")
    print("=" * 70)

    alert_mgr = get_alert_manager()

    print(f"\nEmail configured: {alert_mgr.email_configured}")
    print(f"Slack configured: {alert_mgr.slack_configured}")

    if not alert_mgr.email_configured and not alert_mgr.slack_configured:
        print("\n⚠️  No alerts configured!")
        print("\nTo configure email:")
        print("   export SMTP_USERNAME='your-email@gmail.com'")
        print("   export SMTP_PASSWORD='your-app-password'")
        print("\nTo configure Slack:")
        print("   export SLACK_WEBHOOK_URL='https://hooks.slack.com/services/...'")
        print("\nThen run again.")
    else:
        # Test alert
        print("\n📋 Sending test alert...")

        success, msg = alert_mgr.send_alert(
            alert_id="test-alert-001",
            severity="HIGH",
            title="Test Security Alert",
            message="This is a test alert from the Agentic AI Cybersecurity System.",
            recipients=["admin@example.com"],
            threat_details={
                "Source IP": "192.168.1.100",
                "Attack Type": "Port Scan",
                "Ports Scanned": "1-1000",
                "Timestamp": datetime.utcnow().isoformat()
            },
            alert_type="email" if alert_mgr.email_configured else "slack"
        )

        print(f"   Result: {msg}")

        # Show statistics
        print("\n📊 Statistics:")
        stats = alert_mgr.get_statistics()
        print(f"   Total sent: {stats['total_sent']}")
        print(f"   Failed: {stats['failed']}")

    print("\n" + "=" * 70)
    print("✅ Alert manager test complete!")

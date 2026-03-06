"""
Firewall Manager - Real OS-level IP blocking for macOS and Linux.

This module provides the actual implementation of autonomous IP blocking.
Uses macOS pfctl (packet filter) or Linux iptables depending on OS.

CRITICAL: This module requires sudo privileges to modify firewall rules.

Phase 3 - Day 2: Response Automation
Author: Abhinav
Date: November 2025
"""

import sys
import platform
import subprocess
import logging
import sqlite3
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# CONFIGURATION
# ============================================================================

# Safety whitelist - NEVER block these IPs
WHITELIST = [
    "127.0.0.1",      # localhost
    "::1",            # localhost IPv6
    "0.0.0.0",        # any
    # Add your gateway, DNS, important servers here
    # Example: "192.168.1.1",  # router
]

# Default block duration (minutes)
DEFAULT_BLOCK_DURATION = 10

# Database path for tracking blocked IPs
DB_PATH = Path("data/actions/blocked_ips.db")


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class BlockedIP:
    """Represents a blocked IP address"""
    ip_address: str
    blocked_at: datetime
    expires_at: Optional[datetime]
    reason: str
    ports: Optional[List[int]] = None
    protocol: Optional[str] = None  # 'TCP', 'UDP', or None (all)
    is_permanent: bool = False
    status: str = "active"  # 'active', 'expired', 'unblocked'

    def is_expired(self) -> bool:
        """Check if block has expired"""
        if self.is_permanent:
            return False
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'ip_address': self.ip_address,
            'blocked_at': self.blocked_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'reason': self.reason,
            'ports': ','.join(map(str, self.ports)) if self.ports else None,
            'protocol': self.protocol,
            'is_permanent': self.is_permanent,
            'status': self.status
        }


# ============================================================================
# OS DETECTION
# ============================================================================

def detect_os() -> Tuple[str, str]:
    """
    Detect operating system.
    
    Returns:
        (os_type, os_version) tuple
        os_type: 'macos', 'linux', 'windows', 'unknown'
    """
    system = platform.system().lower()
    version = platform.release()

    if system == 'darwin':
        return ('macos', version)
    elif system == 'linux':
        return ('linux', version)
    elif system == 'windows':
        return ('windows', version)
    else:
        return ('unknown', version)


def check_sudo_access() -> bool:
    """
    Check if script has sudo privileges.
    
    Firewall operations require root/admin access.
    """
    try:
        # Try a harmless sudo command
        result = subprocess.run(
            ['sudo', '-n', 'true'],
            capture_output=True,
            timeout=1
        )
        return result.returncode == 0
    except Exception:
        return False


# ============================================================================
# FIREWALL MANAGER
# ============================================================================

class FirewallManager:
    """
    Cross-platform firewall manager.
    
    Handles IP blocking/unblocking on macOS (pfctl) and Linux (iptables).
    Maintains database of blocked IPs for tracking and auto-expiration.
    """

    def __init__(self, db_path: str = None):
        """
        Initialize firewall manager.
        
        Args:
            db_path: Path to SQLite database for tracking blocks
        """
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.os_type, self.os_version = detect_os()
        self.logger = logging.getLogger(__name__ + ".FirewallManager")

        # Check OS support
        if self.os_type not in ['macos', 'linux']:
            self.logger.error(f"❌ Unsupported OS: {self.os_type}")
            self.supported = False
        else:
            self.supported = True
            self.logger.info(
                f"✅ Detected OS: {self.os_type} {self.os_version}")

        # Check sudo access
        self.has_sudo = check_sudo_access()
        if not self.has_sudo:
            self.logger.warning(
                "⚠️  No sudo access - firewall operations will fail")
            self.logger.warning("   Run with: sudo python3 <script>")
            self.logger.warning(
                "   Or configure passwordless sudo for testing")

        # Initialize database
        self._init_database()

        # Initialize pfctl table on macOS
        if self.os_type == 'macos':
            self._init_pfctl_table()

        self.logger.info("✅ FirewallManager initialized")

    def _init_database(self):
        """Create blocked_ips database table"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip_address TEXT PRIMARY KEY,
                blocked_at TEXT NOT NULL,
                expires_at TEXT,
                reason TEXT,
                ports TEXT,
                protocol TEXT,
                is_permanent INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active'
            )
        """)

        conn.commit()
        conn.close()

        self.logger.info("✅ Blocked IPs database initialized")

    def _init_pfctl_table(self):
        """Initialize pfctl blocklist table on macOS"""
        if not self.has_sudo:
            return

        try:
            # Create blocklist table if it doesn't exist
            # pfctl -t blocklist -T show will fail if table doesn't exist
            result = subprocess.run(
                ['sudo', 'pfctl', '-t', 'blocklist', '-T', 'show'],
                capture_output=True,
                timeout=5
            )

            if result.returncode != 0:
                # Table doesn't exist, need to add it to pf.conf
                self.logger.warning("⚠️  pfctl blocklist table not configured")
                self.logger.info("   For production, add to /etc/pf.conf:")
                self.logger.info("   table <blocklist> persist")
                self.logger.info(
                    "   block drop in quick from <blocklist> to any")
            else:
                self.logger.info("✅ pfctl blocklist table exists")

        except Exception as e:
            self.logger.error(f"Failed to check pfctl table: {e}")

    def is_whitelisted(self, ip_address: str) -> bool:
        """Check if IP is whitelisted (never block)"""
        return ip_address in WHITELIST

    def is_gateway(self, ip_address: str) -> bool:
        """
        Check if IP is the gateway (router).
        
        CRITICAL: Never block the gateway!
        """
        try:
            if self.os_type == 'macos':
                result = subprocess.run(
                    ['netstat', '-nr'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                # Look for default gateway
                for line in result.stdout.split('\n'):
                    if 'default' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            gateway = parts[1]
                            return ip_address == gateway

            return False

        except Exception as e:
            self.logger.warning(f"Could not detect gateway: {e}")
            return False

    def block_ip(
        self,
        ip_address: str,
        reason: str,
        duration_minutes: int = DEFAULT_BLOCK_DURATION,
        ports: Optional[List[int]] = None,
        protocol: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Block an IP address.
        
        Args:
            ip_address: IP to block
            reason: Why blocking (for logging)
            duration_minutes: How long to block (0 = permanent)
            ports: Specific ports to block (None = all ports)
            protocol: 'TCP', 'UDP', or None (all protocols)
            
        Returns:
            (success, message) tuple
        """
        # Safety checks
        if self.is_whitelisted(ip_address):
            msg = f"❌ Cannot block whitelisted IP: {ip_address}"
            self.logger.error(msg)
            return (False, msg)

        if self.is_gateway(ip_address):
            msg = f"❌ Cannot block gateway IP: {ip_address}"
            self.logger.error(msg)
            return (False, msg)

        if not self.supported:
            msg = f"❌ OS not supported: {self.os_type}"
            self.logger.error(msg)
            return (False, msg)

        if not self.has_sudo:
            msg = "❌ No sudo access - cannot modify firewall"
            self.logger.error(msg)
            return (False, msg)

        # Simulation mode — log what would happen, skip actual OS call
        try:
            from src.simulation.simulation_manager import is_simulation, log_simulation_action
            if is_simulation():
                sim_msg = log_simulation_action(
                    f"Would block IP {ip_address}",
                    f"reason={reason}, duration={duration_minutes}min"
                )
                return (True, sim_msg)
        except ImportError:
            pass

        # Calculate expiration
        is_permanent = (duration_minutes == 0)
        blocked_at = datetime.utcnow()
        expires_at = None if is_permanent else blocked_at + \
            timedelta(minutes=duration_minutes)

        # Execute OS-specific block
        if self.os_type == 'macos':
            success, msg = self._block_ip_macos(ip_address)
        elif self.os_type == 'linux':
            success, msg = self._block_ip_linux(ip_address, ports, protocol)
        else:
            return (False, "OS not supported")

        if not success:
            return (False, msg)

        # Store in database
        blocked_ip = BlockedIP(
            ip_address=ip_address,
            blocked_at=blocked_at,
            expires_at=expires_at,
            reason=reason,
            ports=ports,
            protocol=protocol,
            is_permanent=is_permanent,
            status='active'
        )

        self._store_blocked_ip(blocked_ip)

        duration_str = "permanently" if is_permanent else f"for {duration_minutes} minutes"
        success_msg = f"✅ Blocked {ip_address} {duration_str}"
        self.logger.info(success_msg)

        return (True, success_msg)

    def _block_ip_macos(self, ip_address: str) -> Tuple[bool, str]:
        """Block IP on macOS using pfctl"""
        try:
            # Add to blocklist table
            cmd = ['sudo', 'pfctl', '-t', 'blocklist', '-T', 'add', ip_address]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return (True, f"Added {ip_address} to pfctl blocklist")
            else:
                error = result.stderr.strip() if result.stderr else "Unknown error"
                return (False, f"pfctl failed: {error}")

        except subprocess.TimeoutExpired:
            return (False, "pfctl command timed out")
        except Exception as e:
            return (False, f"pfctl exception: {str(e)}")

    def _block_ip_linux(
        self,
        ip_address: str,
        ports: Optional[List[int]],
        protocol: Optional[str]
    ) -> Tuple[bool, str]:
        """Block IP on Linux using iptables"""
        try:
            # Build iptables command
            cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address]

            if protocol:
                cmd.extend(['-p', protocol.lower()])

            if ports:
                if protocol:
                    for port in ports:
                        full_cmd = cmd + ['--dport', str(port), '-j', 'DROP']
                        subprocess.run(
                            full_cmd, capture_output=True, timeout=10)
                else:
                    return (False, "Must specify protocol when blocking specific ports")
            else:
                cmd.extend(['-j', 'DROP'])
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10)

                if result.returncode != 0:
                    return (False, f"iptables failed: {result.stderr}")

            return (True, f"Added {ip_address} to iptables")

        except Exception as e:
            return (False, f"iptables exception: {str(e)}")

    def unblock_ip(self, ip_address: str) -> Tuple[bool, str]:
        """
        Unblock an IP address.
        
        Args:
            ip_address: IP to unblock
            
        Returns:
            (success, message) tuple
        """
        if not self.supported:
            return (False, "OS not supported")

        if not self.has_sudo:
            return (False, "No sudo access")

        # Execute OS-specific unblock
        if self.os_type == 'macos':
            success, msg = self._unblock_ip_macos(ip_address)
        elif self.os_type == 'linux':
            success, msg = self._unblock_ip_linux(ip_address)
        else:
            return (False, "OS not supported")

        if success:
            # Update database
            self._update_blocked_ip_status(ip_address, 'unblocked')
            self.logger.info(f"✅ Unblocked {ip_address}")

        return (success, msg)

    def _unblock_ip_macos(self, ip_address: str) -> Tuple[bool, str]:
        """Unblock IP on macOS"""
        try:
            cmd = ['sudo', 'pfctl', '-t', 'blocklist',
                   '-T', 'delete', ip_address]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                return (True, f"Removed {ip_address} from pfctl blocklist")
            else:
                # IP might not be in table (already unblocked)
                if "no addresses deleted" in result.stderr.lower():
                    return (True, f"{ip_address} was not blocked")
                return (False, f"pfctl failed: {result.stderr}")

        except Exception as e:
            return (False, f"pfctl exception: {str(e)}")

    def _unblock_ip_linux(self, ip_address: str) -> Tuple[bool, str]:
        """Unblock IP on Linux"""
        try:
            cmd = ['sudo', 'iptables', '-D', 'INPUT',
                   '-s', ip_address, '-j', 'DROP']
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                return (True, f"Removed {ip_address} from iptables")
            else:
                if "no chain" in result.stderr.lower() or "does not exist" in result.stderr.lower():
                    return (True, f"{ip_address} was not blocked")
                return (False, f"iptables failed: {result.stderr}")

        except Exception as e:
            return (False, f"iptables exception: {str(e)}")

    def get_blocked_ips(self) -> List[BlockedIP]:
        """Get all currently blocked IPs from database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM blocked_ips WHERE status = 'active'
            """)

            rows = cursor.fetchall()
            conn.close()

            blocked_ips = []
            for row in rows:
                blocked_ip = BlockedIP(
                    ip_address=row['ip_address'],
                    blocked_at=datetime.fromisoformat(row['blocked_at']),
                    expires_at=datetime.fromisoformat(
                        row['expires_at']) if row['expires_at'] else None,
                    reason=row['reason'],
                    ports=[int(p) for p in row['ports'].split(
                        ',')] if row['ports'] else None,
                    protocol=row['protocol'],
                    is_permanent=bool(row['is_permanent']),
                    status=row['status']
                )
                blocked_ips.append(blocked_ip)

            return blocked_ips

        except Exception as e:
            self.logger.error(f"Failed to get blocked IPs: {e}")
            return []

    def cleanup_expired_blocks(self) -> int:
        """
        Remove expired blocks.
        
        Returns:
            Number of blocks removed
        """
        blocked_ips = self.get_blocked_ips()
        removed_count = 0

        for blocked_ip in blocked_ips:
            if blocked_ip.is_expired():
                success, msg = self.unblock_ip(blocked_ip.ip_address)
                if success:
                    removed_count += 1
                    self.logger.info(
                        f"🕐 Auto-unblocked expired: {blocked_ip.ip_address}")

        return removed_count

    def list_active_blocks(self) -> List[str]:
        """Get list of currently blocked IPs from actual firewall"""
        if not self.supported or not self.has_sudo:
            return []

        try:
            if self.os_type == 'macos':
                result = subprocess.run(
                    ['sudo', 'pfctl', '-t', 'blocklist', '-T', 'show'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    return [line.strip() for line in result.stdout.split('\n') if line.strip()]

            elif self.os_type == 'linux':
                result = subprocess.run(
                    ['sudo', 'iptables', '-L', 'INPUT', '-n'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    # Parse iptables output for blocked IPs
                    blocked = []
                    for line in result.stdout.split('\n'):
                        if 'DROP' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                blocked.append(parts[3])
                    return blocked

            return []

        except Exception as e:
            self.logger.error(f"Failed to list active blocks: {e}")
            return []

    def emergency_disable(self) -> Tuple[bool, str]:
        """
        Emergency disable - clear ALL blocks.
        
        USE WITH CAUTION! Removes all firewall blocks.
        """
        if not self.supported or not self.has_sudo:
            return (False, "Cannot execute emergency disable")

        self.logger.warning("⚠️  EMERGENCY DISABLE: Clearing all blocks")

        try:
            if self.os_type == 'macos':
                cmd = ['sudo', 'pfctl', '-t', 'blocklist', '-T', 'flush']
                subprocess.run(cmd, capture_output=True, timeout=10)

            elif self.os_type == 'linux':
                cmd = ['sudo', 'iptables', '-F', 'INPUT']
                subprocess.run(cmd, capture_output=True, timeout=10)

            # Update all in database to unblocked
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("UPDATE blocked_ips SET status = 'unblocked'")
            conn.commit()
            conn.close()

            self.logger.warning("✅ All blocks cleared")
            return (True, "All blocks cleared")

        except Exception as e:
            return (False, f"Emergency disable failed: {str(e)}")

    def _store_blocked_ip(self, blocked_ip: BlockedIP):
        """Store blocked IP in database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            data = blocked_ip.to_dict()
            cursor.execute("""
                INSERT OR REPLACE INTO blocked_ips (
                    ip_address, blocked_at, expires_at, reason,
                    ports, protocol, is_permanent, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data['ip_address'],
                data['blocked_at'],
                data['expires_at'],
                data['reason'],
                data['ports'],
                data['protocol'],
                data['is_permanent'],
                data['status']
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to store blocked IP: {e}")

    def _update_blocked_ip_status(self, ip_address: str, status: str):
        """Update blocked IP status in database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE blocked_ips SET status = ? WHERE ip_address = ?
            """, (status, ip_address))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to update IP status: {e}")


# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

_firewall_instance = None


def get_firewall_manager() -> FirewallManager:
    """Get or create global firewall manager instance"""
    global _firewall_instance

    if _firewall_instance is None:
        _firewall_instance = FirewallManager()

    return _firewall_instance


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    print("Testing Firewall Manager...")
    print("=" * 70)

    fw = get_firewall_manager()

    print(f"\nOS: {fw.os_type} {fw.os_version}")
    print(f"Supported: {fw.supported}")
    print(f"Has sudo: {fw.has_sudo}")

    if not fw.has_sudo:
        print("\n⚠️  Run with sudo to test blocking:")
        print("   sudo python3 src/actions/firewall_manager.py")
        sys.exit(0)

    # Test with safe IP (not real blocking)
    test_ip = "1.2.3.4"  # Fake IP for testing

    print(f"\n📋 Test 1: Block {test_ip}")
    success, msg = fw.block_ip(test_ip, "Test block", duration_minutes=1)
    print(f"   Result: {msg}")

    print("\n📋 Test 2: List active blocks")
    active = fw.list_active_blocks()
    print(f"   Active blocks: {active}")

    print("\n📋 Test 3: Get blocked IPs from DB")
    blocked = fw.get_blocked_ips()
    for b in blocked:
        print(f"   - {b.ip_address}: {b.reason} (expires: {b.expires_at})")

    print(f"\n📋 Test 4: Unblock {test_ip}")
    success, msg = fw.unblock_ip(test_ip)
    print(f"   Result: {msg}")

    print("\n📋 Test 5: Verify unblocked")
    active = fw.list_active_blocks()
    print(f"   Active blocks: {active}")

    print("\n" + "=" * 70)
    print("✅ Firewall manager test complete!")

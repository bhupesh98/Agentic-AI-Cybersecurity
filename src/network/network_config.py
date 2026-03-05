"""
Network Configuration Utility for Two-MacBook Setup
Handles dynamic IP discovery and connectivity testing between attacker and defender machines.

Location: src/network/network_config.py
"""

import socket
import subprocess
import json
from pathlib import Path
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class NetworkConfig:
    """Network configuration for two-MacBook setup."""
    defender_ip: str
    attacker_ip: Optional[str] = None
    defender_port: int = 9000  # Port for receiving attack data
    attacker_port: int = 9001  # Port for attack generation
    hotspot_ip: str = "192.0.0.2"  # Hotspot IP (Private Relay)


class NetworkConfigManager:
    """Manages network configuration for attacker-defender setup."""

    def __init__(self, config_dir: str = "data/network"):
        """
        Initialize network config manager.
        
        Args:
            config_dir: Directory to store network configuration
        """
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.config_dir / "network_config.json"

    def get_local_ip(self) -> str:
        """
        Get the local IP address of this machine.
        Works even with Apple Private Relay enabled.
        
        Returns:
            Local IP address as string
        """
        try:
            # Method 1: Connect to external address to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            # Connect to Google DNS (doesn't actually send data)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            # Method 2: Use hostname resolution
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                return local_ip
            except Exception:
                # Method 3: Parse ifconfig output (macOS specific)
                try:
                    result = subprocess.run(
                        ["ifconfig"],
                        capture_output=True,
                        text=True
                    )
                    for line in result.stdout.split('\n'):
                        if 'inet ' in line and '127.0.0.1' not in line:
                            ip = line.split()[1]
                            # Filter out Private Relay IPs if possible
                            if not ip.startswith('169.254'):  # Ignore link-local
                                return ip
                except Exception:
                    pass

                return "127.0.0.1"  # Fallback to localhost

    def get_network_interfaces(self) -> Dict[str, str]:
        """
        Get all network interfaces and their IPs.
        
        Returns:
            Dictionary mapping interface names to IP addresses
        """
        interfaces = {}
        try:
            result = subprocess.run(
                ["ifconfig"],
                capture_output=True,
                text=True
            )

            current_interface = None
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and not line.startswith(' ') and not line.startswith('\t'):
                    # New interface
                    current_interface = line.split(':')[0]
                elif 'inet ' in line and current_interface:
                    ip = line.split()[1]
                    if ip != '127.0.0.1' and not ip.startswith('169.254'):
                        interfaces[current_interface] = ip
        except Exception as e:
            print(f"Error getting network interfaces: {e}")

        return interfaces

    def test_connectivity(self, target_ip: str, port: int = 9000, timeout: float = 2.0) -> bool:
        """
        Test if we can connect to target IP and port.
        
        Args:
            target_ip: IP address to test
            port: Port to test
            timeout: Connection timeout in seconds
            
        Returns:
            True if connection successful, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            return result == 0
        except Exception as e:
            print(f"Connectivity test failed: {e}")
            return False

    def ping_host(self, target_ip: str, count: int = 3) -> Tuple[bool, float]:
        """
        Ping a host to test network connectivity.
        
        Args:
            target_ip: IP address to ping
            count: Number of ping packets
            
        Returns:
            Tuple of (success, average_latency_ms)
        """
        try:
            result = subprocess.run(
                ["ping", "-c", str(count), target_ip],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Parse average latency from ping output
                for line in result.stdout.split('\n'):
                    if 'avg' in line.lower():
                        # Format: "round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.123 ms"
                        parts = line.split('=')[1].split('/')
                        avg_latency = float(parts[1])
                        return True, avg_latency
                return True, 0.0
            else:
                return False, 0.0
        except Exception as e:
            print(f"Ping failed: {e}")
            return False, 0.0

    def save_config(self, config: NetworkConfig) -> None:
        """
        Save network configuration to file.
        
        Args:
            config: NetworkConfig object to save
        """
        with open(self.config_file, 'w') as f:
            json.dump(asdict(config), f, indent=2)
        print(f"✅ Network config saved to: {self.config_file}")

    def load_config(self) -> Optional[NetworkConfig]:
        """
        Load network configuration from file.
        
        Returns:
            NetworkConfig object or None if not found
        """
        if not self.config_file.exists():
            return None

        try:
            with open(self.config_file, 'r') as f:
                data = json.load(f)
            return NetworkConfig(**data)
        except Exception as e:
            print(f"Error loading config: {e}")
            return None

    def setup_defender(self) -> NetworkConfig:
        """
        Setup network configuration for defender machine.
        This should be run on the M4 MacBook Pro.
        
        Returns:
            NetworkConfig object
        """
        print("=" * 60)
        print("DEFENDER MACHINE SETUP (M4 MacBook Pro)")
        print("=" * 60)

        # Get local IP
        defender_ip = self.get_local_ip()
        print(f"\n📍 Defender IP detected: {defender_ip}")

        # Show all interfaces
        interfaces = self.get_network_interfaces()
        if interfaces:
            print("\n🌐 Available network interfaces:")
            for iface, ip in interfaces.items():
                print(f"   {iface}: {ip}")

        # Allow manual override
        print(f"\n💡 Press Enter to use detected IP ({defender_ip})")
        print("   Or enter a different IP address:")
        user_input = input("   > ").strip()
        if user_input:
            defender_ip = user_input

        # Ask for attacker IP
        print("\n🎯 Enter attacker machine IP address:")
        print("   (Leave empty if not known yet)")
        attacker_ip = input("   > ").strip() or None

        config = NetworkConfig(
            defender_ip=defender_ip,
            attacker_ip=attacker_ip
        )

        self.save_config(config)

        print("\n" + "=" * 60)
        print("✅ DEFENDER SETUP COMPLETE")
        print("=" * 60)
        print(f"Defender IP: {config.defender_ip}")
        print(f"Listening Port: {config.defender_port}")
        if attacker_ip:
            print(f"Attacker IP: {config.attacker_ip}")
        print("=" * 60)

        return config

    def setup_attacker(self, defender_ip: str) -> NetworkConfig:
        """
        Setup network configuration for attacker machine.
        This should be run on the Intel MacBook Pro 2017.
        
        Args:
            defender_ip: IP address of defender machine
            
        Returns:
            NetworkConfig object
        """
        print("=" * 60)
        print("ATTACKER MACHINE SETUP (Intel MacBook Pro 2017)")
        print("=" * 60)

        # Get local IP
        attacker_ip = self.get_local_ip()
        print(f"\n📍 Attacker IP detected: {attacker_ip}")

        # Show all interfaces
        interfaces = self.get_network_interfaces()
        if interfaces:
            print("\n🌐 Available network interfaces:")
            for iface, ip in interfaces.items():
                print(f"   {iface}: {ip}")

        # Allow manual override
        print(f"\n💡 Press Enter to use detected IP ({attacker_ip})")
        print("   Or enter a different IP address:")
        user_input = input("   > ").strip()
        if user_input:
            attacker_ip = user_input

        config = NetworkConfig(
            defender_ip=defender_ip,
            attacker_ip=attacker_ip
        )

        self.save_config(config)

        print("\n" + "=" * 60)
        print("✅ ATTACKER SETUP COMPLETE")
        print("=" * 60)
        print(f"Attacker IP: {config.attacker_ip}")
        print(f"Defender IP: {config.defender_ip}")
        print(f"Target Port: {config.defender_port}")
        print("=" * 60)

        return config

    def test_network_setup(self) -> None:
        """
        Test the network setup between attacker and defender.
        """
        config = self.load_config()
        if not config:
            print("❌ No network configuration found. Run setup first.")
            return

        print("\n" + "=" * 60)
        print("NETWORK CONNECTIVITY TEST")
        print("=" * 60)

        print(f"\n📍 Local IP: {self.get_local_ip()}")
        print(f"📍 Defender IP: {config.defender_ip}")
        if config.attacker_ip:
            print(f"📍 Attacker IP: {config.attacker_ip}")

        # Test ping to defender
        print(
            f"\n🔍 Testing connectivity to defender ({config.defender_ip})...")
        success, latency = self.ping_host(config.defender_ip)
        if success:
            print(f"   ✅ Ping successful! Average latency: {latency:.2f} ms")
        else:
            print("   ❌ Ping failed. Check network connection.")

        # Test ping to attacker if known
        if config.attacker_ip:
            print(
                f"\n🔍 Testing connectivity to attacker ({config.attacker_ip})...")
            success, latency = self.ping_host(config.attacker_ip)
            if success:
                print(
                    f"   ✅ Ping successful! Average latency: {latency:.2f} ms")
            else:
                print("   ❌ Ping failed. Check network connection.")

        print("\n" + "=" * 60)


def main():
    """Main function for interactive setup."""
    manager = NetworkConfigManager()

    print("\n" + "=" * 60)
    print("TWO-MACBOOK NETWORK SETUP")
    print("=" * 60)
    print("\nSelect machine role:")
    print("1. Defender (M4 MacBook Pro - runs Agentic AI)")
    print("2. Attacker (Intel MacBook Pro 2017 - generates attacks)")
    print("3. Test existing setup")
    print("4. Show current configuration")

    choice = input("\nEnter choice (1-4): ").strip()

    if choice == "1":
        manager.setup_defender()
        print("\n💡 Next: Run this script on the attacker machine with option 2")
    elif choice == "2":
        defender_ip = input("\nEnter defender IP address: ").strip()
        if not defender_ip:
            print("❌ Defender IP required!")
            return
        manager.setup_attacker(defender_ip)
        print("\n💡 Setup complete! You can now run attack simulations.")
    elif choice == "3":
        manager.test_network_setup()
    elif choice == "4":
        config = manager.load_config()
        if config:
            print("\n📋 Current Configuration:")
            print(f"   Defender IP: {config.defender_ip}")
            print(f"   Defender Port: {config.defender_port}")
            if config.attacker_ip:
                print(f"   Attacker IP: {config.attacker_ip}")
                print(f"   Attacker Port: {config.attacker_port}")
        else:
            print("\n❌ No configuration found. Run setup first.")
    else:
        print("❌ Invalid choice!")


if __name__ == "__main__":
    main()

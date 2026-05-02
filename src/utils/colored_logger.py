"""
Colorized Logger Utility for Agentic AI Cybersecurity System

Provides beautiful, consistent terminal output with colors, emojis, and formatting.
Used across all modules for unified visual presentation.

Location: src/utils/colored_logger.py

"""

from colorama import Fore, Style, init
from typing import Optional, List, Dict, Any
from datetime import datetime
import sys

# Initialize colorama
init(autoreset=True)


class ColoredLogger:
    """
    Provides colorized logging with consistent styling.
    
    Color Scheme:
    - RED: Critical threats, errors, repeat offenders
    - YELLOW: Warnings, medium threats, context flags
    - GREEN: Success, benign traffic, verifications
    - CYAN: Info, headers, statistics
    - MAGENTA: LLM reasoning, AI decisions
    - BLUE: System messages, workflow phases
    """

    def __init__(self, module_name: str = "System"):
        """
        Initialize logger for a specific module.
        
        Args:
            module_name: Name of the module using this logger
        """
        self.module_name = module_name

    # ========================================================================
    # HEADER & SEPARATORS
    # ========================================================================

    @staticmethod
    def print_header(title: str, width: int = 70, color: str = Fore.CYAN):
        """Print a prominent header."""
        print(f"\n{color}{Style.BRIGHT}{'=' * width}")
        print(f"{title.center(width)}")
        print(f"{'=' * width}{Style.RESET_ALL}\n")

    @staticmethod
    def print_separator(char: str = "─", width: int = 70, color: str = Fore.CYAN):
        """Print a separator line."""
        print(f"{color}{char * width}{Style.RESET_ALL}")

    @staticmethod
    def print_section(title: str, width: int = 70, color: str = Fore.CYAN):
        """Print a section header."""
        print(f"\n{color}{Style.BRIGHT}{title}")
        print(f"{'-' * len(title)}{Style.RESET_ALL}")

    # ========================================================================
    # STATUS MESSAGES
    # ========================================================================

    def success(self, message: str, prefix: str = "✅"):
        """Print success message in green."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.GREEN}[{timestamp}] {prefix} {message}{Style.RESET_ALL}")

    def error(self, message: str, prefix: str = "❌"):
        """Print error message in red."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.RED}[{timestamp}] {prefix} {message}{Style.RESET_ALL}")

    def warning(self, message: str, prefix: str = "⚠️"):
        """Print warning message in yellow."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(
            f"{Fore.YELLOW}[{timestamp}] {prefix} {message}{Style.RESET_ALL}")

    def info(self, message: str, prefix: str = "ℹ️"):
        """Print info message in cyan."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.CYAN}[{timestamp}] {prefix} {message}{Style.RESET_ALL}")

    def debug(self, message: str, prefix: str = "🔍"):
        """Print debug message in blue."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.BLUE}[{timestamp}] {prefix} {message}{Style.RESET_ALL}")

    # ========================================================================
    # THREAT DETECTION
    # ========================================================================

    @staticmethod
    def threat_critical(message: str):
        """Print critical threat in red with emphasis."""
        print(f"{Fore.RED}{Style.BRIGHT}🚨 CRITICAL: {message}{Style.RESET_ALL}")

    @staticmethod
    def threat_high(message: str):
        """Print high threat in red."""
        print(f"{Fore.RED}🔴 HIGH: {message}{Style.RESET_ALL}")

    @staticmethod
    def threat_medium(message: str):
        """Print medium threat in yellow."""
        print(f"{Fore.YELLOW}🟡 MEDIUM: {message}{Style.RESET_ALL}")

    @staticmethod
    def threat_low(message: str):
        """Print low threat in yellow."""
        print(f"{Fore.YELLOW}🟢 LOW: {message}{Style.RESET_ALL}")

    @staticmethod
    def threat_benign(message: str):
        """Print benign traffic in green."""
        print(f"{Fore.GREEN}✓ BENIGN: {message}{Style.RESET_ALL}")

    # ========================================================================
    # DETECTION COMPONENTS
    # ========================================================================

    @staticmethod
    def ml_prediction(model: str, prediction: str, confidence: float):
        """Print ML model prediction."""
        color = Fore.RED if prediction == 'malicious' else Fore.GREEN
        print(f"{Fore.CYAN}   ├─ {model}: {color}{prediction}{Fore.CYAN} ({confidence:.1%}){Style.RESET_ALL}")

    @staticmethod
    def llm_analysis(severity: str, reasoning: str, max_length: int = 100):
        """Print LLM analysis."""
        severity_colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.YELLOW
        }
        color = severity_colors.get(severity.upper(), Fore.CYAN)

        # Truncate reasoning if too long
        if len(reasoning) > max_length:
            reasoning = reasoning[:max_length] + "..."

        print(f"{Fore.MAGENTA}🤖 LLM Analysis: {color}{severity}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}   \"{reasoning}\"{Style.RESET_ALL}")

    @staticmethod
    def memory_context(is_repeat: bool, incident_count: int, threat_score: float):
        """Print memory context."""
        if is_repeat:
            print(f"{Fore.RED}🧠 Memory Context:{Style.RESET_ALL}")
            print(
                f"{Fore.RED}   ⚠️  REPEAT OFFENDER: {incident_count} previous incidents{Style.RESET_ALL}")
            print(
                f"{Fore.RED}   🎯 Threat Score: {threat_score:.2f}/1.0 (Hybrid ML+LLM){Style.RESET_ALL}")
        else:
            print(
                f"{Fore.CYAN}🧠 Memory Context: First incident from this IP{Style.RESET_ALL}")

    @staticmethod
    def action_taken(action: str, success: bool, details: str = ""):
        """Print action execution result."""
        if success:
            print(f"{Fore.GREEN}⚡ Action: {action} ✅{Style.RESET_ALL}")
            if details:
                print(f"{Fore.GREEN}   {details}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}⚡ Action: {action} ❌{Style.RESET_ALL}")
            if details:
                print(f"{Fore.RED}   {details}{Style.RESET_ALL}")

    # ========================================================================
    # STATISTICS & METRICS
    # ========================================================================

    @staticmethod
    def print_stats(title: str, stats: Dict[str, Any], color: str = Fore.CYAN):
        """Print statistics in a formatted way."""
        print(f"\n{color}{Style.BRIGHT}📊 {title}{Style.RESET_ALL}")
        for key, value in stats.items():
            # Format key (replace underscores with spaces, capitalize)
            formatted_key = key.replace('_', ' ').title()

            # Format value based on type
            if isinstance(value, float):
                if 0 < value < 1:
                    formatted_value = f"{value:.1%}"
                else:
                    formatted_value = f"{value:.2f}"
            else:
                formatted_value = str(value)

            print(
                f"{color}   {formatted_key}: {Fore.WHITE}{formatted_value}{Style.RESET_ALL}")

    @staticmethod
    def print_progress(current: int, total: int, prefix: str = "", suffix: str = ""):
        """Print progress bar."""
        filled = int(40 * current / total)
        bar = '█' * filled + '░' * (40 - filled)
        percent = 100 * current / total

        print(
            f"\r{Fore.CYAN}{prefix} [{bar}] {percent:.0f}% {suffix}{Style.RESET_ALL}", end='')
        if current == total:
            print()  # New line when complete

    # ========================================================================
    # THREAT DETECTION BOX
    # ========================================================================

    @staticmethod
    def print_threat_box(
        threat_type: str,
        source: str,
        destination: str,
        severity: str,
        ml_confidence: float,
        llm_reasoning: str,
        memory_info: Optional[Dict] = None,
        actions: Optional[List[str]] = None
    ):
        """
        Print a comprehensive threat detection box.
        
        Args:
            threat_type: Type of threat (e.g., "SSH Brute Force")
            source: Source IP:port
            destination: Destination IP:port
            severity: Threat severity level
            ml_confidence: ML model confidence
            llm_reasoning: LLM analysis text
            memory_info: Optional memory context
            actions: Optional list of actions taken
        """
        # Determine colors based on severity
        severity_colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.YELLOW
        }
        color = severity_colors.get(severity.upper(), Fore.CYAN)

        print(f"\n{color}{'─' * 70}{Style.RESET_ALL}")
        print(
            f"{color}{Style.BRIGHT}🔴 THREAT DETECTED - {threat_type}{Style.RESET_ALL}")
        print(f"{color}{'─' * 70}{Style.RESET_ALL}")

        # Connection info
        print(f"{Fore.WHITE}Source: {Fore.CYAN}{source}{Style.RESET_ALL} → "
              f"{Fore.WHITE}Destination: {Fore.CYAN}{destination}{Style.RESET_ALL}")

        # ML prediction
        print(f"\n{Fore.CYAN}ML Ensemble: {color}{severity.upper()}{Fore.CYAN} "
              f"({ml_confidence:.1%} confidence){Style.RESET_ALL}")

        # LLM analysis
        print(f"\n{Fore.MAGENTA}🤖 LLM Analysis:{Style.RESET_ALL}")
        # Wrap reasoning text
        max_width = 65
        words = llm_reasoning.split()
        line = "   "
        for word in words:
            if len(line) + len(word) + 1 > max_width:
                print(f"{Fore.MAGENTA}{line}{Style.RESET_ALL}")
                line = "   " + word
            else:
                line += " " + word
        if line.strip():
            print(f"{Fore.MAGENTA}{line}{Style.RESET_ALL}")

        # Memory context
        if memory_info:
            print(f"\n{Fore.YELLOW}🧠 Memory Context:{Style.RESET_ALL}")
            if memory_info.get('is_repeat_offender'):
                print(f"{Fore.RED}   ⚠️  REPEAT OFFENDER: "
                      f"{memory_info.get('incident_count', 0)} previous incidents{Style.RESET_ALL}")
            if 'threat_score' in memory_info:
                print(f"{Fore.YELLOW}   🎯 Threat Score: "
                      f"{memory_info['threat_score']:.2f}/1.0{Style.RESET_ALL}")

        # Actions taken
        if actions:
            print(f"\n{Fore.GREEN}⚡ Autonomous Response:{Style.RESET_ALL}")
            for action in actions:
                print(f"{Fore.GREEN}   ✅ {action}{Style.RESET_ALL}")

        print(f"{color}{'─' * 70}{Style.RESET_ALL}\n")

    # ========================================================================
    # SYSTEM STATUS
    # ========================================================================

    @staticmethod
    def print_system_status(
        status: str,
        flows_detected: int,
        active_flows: int,
        threats: int,
        false_positives: int,
        agentic_score: float
    ):
        """Print system status line."""
        status_color = Fore.GREEN if status == "ACTIVE" else Fore.RED

        print(f"\r{Fore.CYAN}[{datetime.now().strftime('%H:%M:%S')}] "
              f"{status_color}● {status}{Fore.CYAN} | "
              f"Flows: {Fore.WHITE}{flows_detected}{Fore.CYAN} ({Fore.YELLOW}{active_flows}{Fore.CYAN} active) | "
              f"Threats: {Fore.RED}{threats}{Fore.CYAN} | "
              f"FP: {Fore.YELLOW}{false_positives}{Fore.CYAN} | "
              f"Agentic Score: {Fore.GREEN}{agentic_score:.1%}{Style.RESET_ALL}", end='')
        sys.stdout.flush()

    # ========================================================================
    # ATTACK GENERATION
    # ========================================================================

    @staticmethod
    def attack_start(attack_type: str, target: str, rate: int, duration: int):
        """Print attack generation start."""
        print(f"\n{Fore.RED}{Style.BRIGHT}{'═' * 70}")
        print(f"{'🔴 ATTACK GENERATOR'.center(70)}")
        print(f"{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.RED}Attack Type: {Fore.WHITE}{attack_type}{Style.RESET_ALL}")
        print(f"{Fore.RED}Target: {Fore.WHITE}{target}{Style.RESET_ALL}")
        print(f"{Fore.RED}Rate: {Fore.WHITE}{rate} packets/sec{Style.RESET_ALL}")
        print(f"{Fore.RED}Duration: {Fore.WHITE}{duration} seconds{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═' * 70}{Style.RESET_ALL}\n")

    @staticmethod
    def attack_progress(packets_sent: int, total_packets: int, elapsed: float):
        """Print attack generation progress."""
        filled = int(40 * packets_sent /
                     total_packets) if total_packets > 0 else 0
        bar = '█' * filled + '░' * (40 - filled)
        percent = 100 * packets_sent / total_packets if total_packets > 0 else 0

        print(f"\r{Fore.RED}Progress: [{bar}] {percent:.0f}% | "
              f"Sent: {packets_sent}/{total_packets} | "
              f"Time: {elapsed:.1f}s{Style.RESET_ALL}", end='')
        sys.stdout.flush()

    @staticmethod
    def attack_complete(attack_type: str, packets_sent: int, duration: float):
        """Print attack completion."""
        print(
            f"\n\n{Fore.GREEN}✅ Attack Complete: {attack_type}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}   Packets sent: {packets_sent}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}   Duration: {duration:.2f}s{Style.RESET_ALL}")
        print(
            f"{Fore.GREEN}   Avg rate: {packets_sent/duration:.1f} pps{Style.RESET_ALL}\n")


# ============================================================================
# GLOBAL LOGGER INSTANCE
# ============================================================================

_global_logger = None


def get_logger(module_name: str = "System") -> ColoredLogger:
    """
    Get or create a logger instance.
    
    Args:
        module_name: Name of the module
        
    Returns:
        ColoredLogger instance
    """
    return ColoredLogger(module_name)


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def print_banner(title: str, subtitle: str = ""):
    """Print application banner."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═' * 70}")
    print(f"{title.center(70)}")
    if subtitle:
        print(f"{subtitle.center(70)}")
    print(f"{'═' * 70}{Style.RESET_ALL}\n")


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    """Test the colored logger."""

    print_banner("COLORED LOGGER TEST", "Agentic AI Cybersecurity System")

    logger = get_logger("TestModule")

    # Test headers
    logger.print_header("DETECTION WORKFLOW")

    # Test status messages
    logger.success("System initialized successfully")
    logger.info("Loading ML models...")
    logger.warning("Low memory available")
    logger.error("Failed to connect to database")
    logger.debug("Packet capture rate: 100 pps")

    # Test threat levels
    print("\n")
    logger.threat_critical("SQL Injection detected!")
    logger.threat_high("Brute force attempt")
    logger.threat_medium("Suspicious port scan")
    logger.threat_low("Unusual traffic pattern")
    logger.threat_benign("Normal HTTP request")

    # Test ML predictions
    print("\n")
    ColoredLogger.print_section("ML ENSEMBLE PREDICTIONS")
    ColoredLogger.ml_prediction("Random Forest", "malicious", 0.94)
    ColoredLogger.ml_prediction("XGBoost", "malicious", 0.99)
    ColoredLogger.ml_prediction("DNN", "benign", 0.87)

    # Test LLM analysis
    print("\n")
    ColoredLogger.llm_analysis(
        "HIGH",
        "Multiple failed SSH login attempts detected from unknown IP. "
        "Pattern matches known brute force attack signature."
    )

    # Test memory context
    print("\n")
    ColoredLogger.memory_context(True, 3, 0.85)

    # Test actions
    print("\n")
    ColoredLogger.action_taken(
        "Block IP 192.168.1.100", True, "Blocked for 10 minutes")
    ColoredLogger.action_taken("Send email alert", True)

    # Test statistics
    print("\n")
    stats = {
        'total_flows': 1523,
        'threats_detected': 47,
        'false_positive_rate': 0.023,
        'detection_accuracy': 0.962,
        'avg_response_time': 1.24
    }
    ColoredLogger.print_stats("SYSTEM STATISTICS", stats)

    # Test progress bar
    print("\n")
    ColoredLogger.print_section("PROGRESS BAR TEST")
    import time
    for i in range(101):
        ColoredLogger.print_progress(i, 100, "Processing", f"{i}/100")
        time.sleep(0.02)

    # Test threat box
    ColoredLogger.print_threat_box(
        threat_type="SSH Brute Force Attack",
        source="192.168.1.100:54321",
        destination="10.0.0.50:22",
        severity="HIGH",
        ml_confidence=0.96,
        llm_reasoning="Rapid connection attempts to SSH port with no successful handshakes. "
        "Classic brute force pattern indicating automated attack tool.",
        memory_info={
            'is_repeat_offender': True,
            'incident_count': 3,
            'threat_score': 0.85
        },
        actions=[
            "IP Blocked (10 min)",
            "Alert sent to admin@example.com",
            "Incident stored in memory"
        ]
    )

    # Test system status
    print("\n")
    ColoredLogger.print_section("SYSTEM STATUS TEST")
    for i in range(5):
        ColoredLogger.print_system_status(
            status="ACTIVE",
            flows_detected=100 + i * 10,
            active_flows=3 + i,
            threats=2 + i,
            false_positives=1,
            agentic_score=0.888
        )
        time.sleep(1)
    print("\n")

    # Test attack generator display
    ColoredLogger.attack_start(
        attack_type="SSH Brute Force",
        target="127.0.0.1:22",
        rate=50,
        duration=10
    )

    for i in range(101):
        ColoredLogger.attack_progress(i, 100, i * 0.02)
        time.sleep(0.02)

    ColoredLogger.attack_complete("SSH Brute Force", 100, 2.0)

    print(f"\n{Fore.GREEN}{Style.BRIGHT}{'═' * 70}")
    print(f"{'✅ COLORED LOGGER TEST COMPLETE'.center(70)}")
    print(f"{'═' * 70}{Style.RESET_ALL}\n")

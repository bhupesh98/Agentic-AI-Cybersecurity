# Comprehensive APT Testing Framework

## Overview

This framework provides comprehensive testing and validation of APT (Advanced Persistent Threat) detection capabilities. It addresses the critical requirement of identifying **at which stage of the APT lifecycle** attacks are detected and what incident responses are triggered.

## Key Features

1. **Realistic APT Scenarios**: Based on real-world APT groups (APT28, APT29, Lazarus)
2. **Stage-by-Stage Tracking**: Tracks detection at each stage of the APT lifecycle
3. **Comprehensive Metrics**: Measures detection effectiveness, time-to-detect, and response quality
4. **Minimally Invasive**: Uses existing infrastructure without modification

## APT Lifecycle Stages (MITRE ATT&CK Aligned)

The framework tracks detection across these stages:

1. **Reconnaissance** - Initial information gathering
2. **Initial Access** - First compromise of the target
3. **Execution** - Running malicious code
4. **Persistence** - Maintaining access
5. **Privilege Escalation** - Gaining higher privileges
6. **Defense Evasion** - Avoiding detection
7. **Credential Access** - Stealing credentials
8. **Discovery** - Learning about the environment
9. **Lateral Movement** - Moving through the network
10. **Collection** - Gathering data of interest
11. **Command and Control** - Communicating with C2 servers
12. **Exfiltration** - Stealing data
13. **Impact** - Disrupting operations

## Detection Quality Metrics

The framework evaluates detection quality based on when detection occurs:

- **EXCELLENT**: Detected in Reconnaissance or Initial Access (early detection)
- **GOOD**: Detected in Execution or Persistence
- **ACCEPTABLE**: Detected in Lateral Movement or Collection
- **POOR**: Detected in Exfiltration or later (late detection)
- **FAILED**: Not detected at all

## Available Scenarios

### 1. APT28 (Fancy Bear) Style
- **Stages**: 7 stages
- **Characteristics**: Spear phishing, credential theft, SMB lateral movement
- **Expected Detection**: Initial Access or Execution
- **Stealth Level**: Medium

### 2. APT29 (Cozy Bear) Style
- **Stages**: 4 stages
- **Characteristics**: Long-term persistence, stealthy C2, living-off-the-land
- **Expected Detection**: Command and Control (very stealthy)
- **Stealth Level**: High

### 3. Lazarus Group Style
- **Stages**: 5 stages
- **Characteristics**: Fast-moving, financial theft focus, destructive capabilities
- **Expected Detection**: Initial Access or Discovery
- **Stealth Level**: Low (noisy attacks)

### 4. Silent Shadow (Custom)
- **Stages**: 4 stages
- **Characteristics**: Stealthy reconnaissance, zero-day exploit, data exfiltration
- **Expected Detection**: Initial Access or Lateral Movement
- **Stealth Level**: Medium-High

## Usage

### Running All Scenarios

```bash
cd /Users/rishabh/Documents/Documents/Agentic-AI-Cybersecurity
sudo python3 test_comprehensive_apt_scenarios.py
```

### Running a Single Scenario

```python
from src.network.apt_test_framework import APTScenarioGenerator
from test_comprehensive_apt_scenarios import APTTestRunner

runner = APTTestRunner()
result = runner.run_scenario("APT28_Style", verbose=True)
```

### Programmatic Usage

```python
from src.network.apt_test_framework import APTScenarioGenerator, APTStage
from src.metrics.apt_metrics import APTMetrics

# Generate scenario
generator = APTScenarioGenerator()
stages = generator.generate_scenario("APT28_Style", "192.168.1.250", "10.0.0.100")

# Run through workflow and collect metrics
# ... (see test_comprehensive_apt_scenarios.py for full example)
```

## Output Files

### Individual Test Results
- Location: `reports/apt_tests/{scenario_name}_{session_id}.json`
- Contains: Complete test results, detection events, response actions

### Aggregated Report
- Location: `reports/apt_tests/apt_test_report_{timestamp}.json`
- Contains: Summary statistics across all tests, detection quality distribution

## Metrics Collected

### Detection Metrics
- **Detection Rate**: Percentage of attacks detected
- **Time to Detect**: Average time from attack start to detection
- **Detection Stage**: Which lifecycle stage detection occurred
- **Detection Method**: ML, LLM, Context, or Memory-based
- **Detection Quality**: Excellent, Good, Acceptable, Poor, or Failed

### Response Metrics
- **Response Time**: Time from detection to first response action
- **Actions Taken**: Number of response actions executed
- **Success Rate**: Percentage of successful response actions
- **Response Types**: Types of actions taken (block_ip, alert, etc.)

### Stage-by-Stage Analysis
- Tracks whether each stage was detected
- Identifies which stages are most/least detectable
- Helps identify detection gaps

## Interpreting Results

### Good Results
- Detection in **Reconnaissance** or **Initial Access** stages
- High detection rate (>90%)
- Low time-to-detect (<5 minutes)
- Successful response actions

### Areas for Improvement
- Detection only in **Exfiltration** or later stages
- Low detection rate (<70%)
- High time-to-detect (>30 minutes)
- Failed response actions

## Integration with Existing System

The framework:
- ✅ Uses existing workflow (`src/agent/workflow_graph.py`)
- ✅ Uses existing ML models
- ✅ Uses existing LLM client
- ✅ Uses existing action executors
- ✅ Uses existing metrics system
- ✅ **Does NOT modify** any existing code

## Architecture

```
test_comprehensive_apt_scenarios.py
    ├── APTTestRunner
    │   ├── Runs scenarios through workflow
    │   ├── Tracks detections
    │   └── Executes responses
    │
src/network/apt_test_framework.py
    ├── APTScenarioGenerator
    │   ├── Generates realistic APT scenarios
    │   └── Creates network flows for each stage
    │
src/metrics/apt_metrics.py
    ├── APTMetrics
    │   ├── Calculates detection metrics
    │   └── Evaluates detection quality
    │
    └── APTMetricsAggregator
        └── Aggregates results across tests
```

## Example Output

```
🔴 RUNNING APT SCENARIO: APT28_Style
================================================================================

📋 Scenario: APT28_Style
   Attacker: 192.168.1.250
   Target: 10.0.0.100
   Total Stages: 7

   Stages:
     1. Reconnaissance
        Expected Detection: Initial Access
     2. Initial Access
        Expected Detection: Initial Access
     ...

🔄 Executing workflow with APT flows...

📊 Detection Results:
   ✅ DETECTED at Stage: Initial Access
   Detection Method: LLM
   Time to Detect: 35.2 seconds
   Severity: HIGH

⚡ Executing Autonomous Response...
   ✅ Block IP: Blocked 192.168.1.250 for 60 minutes
   ✅ Email Alert: Email sent to 1 recipients

💾 Test results saved to: reports/apt_tests/APT28_Style_apt-test-20251204-123456.json
   Detection Quality: excellent
```

## Future Enhancements

Potential improvements:
1. Integration with MITRE ATT&CK framework for more scenarios
2. Real-time network packet capture and analysis
3. Integration with attack simulation tools (Caldera, Atomic Red Team)
4. Automated report generation with visualizations
5. Baseline comparison against industry standards

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- APT Groups: https://attack.mitre.org/groups/
- Detection Quality Standards: NIST Cybersecurity Framework

## Author

Abhinav - December 2025


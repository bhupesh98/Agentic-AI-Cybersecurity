# Agentic AI Cybersecurity System

An autonomous cybersecurity system that uses Agentic AI principles to detect and respond to Advanced Persistent Threats (APTs) through ML ensemble detection, LLM reasoning, memory correlation, and autonomous response actions.

## Project Overview

This system implements 7 Agentic AI principles (Self-Learning, Contextual Awareness, Goal-Directed, Tool Utilization, Planning & Reasoning, Memory Management, Feedback Incorporation) to autonomously detect, analyze, and respond to sophisticated cyber attacks.

---

## Directory Structure

- **`src/`** - Core source code organized by functional modules (agent, network, memory, metrics, actions, etc.)
- **`data/`** - Data storage including metrics, memory databases, processed datasets, and network configurations
- **`models/`** - Trained ML models (RandomForest, XGBoost, DNN) and associated files (scalers, encoders, weights)
- **`notebooks/`** - Jupyter notebooks for data analysis, model training, and system testing
- **`outputs/`** - Generated visualizations (plots, metrics tables) and analysis results
- **`reports/`** - APT test reports and analysis summaries
- **`datasets/`** - Raw and processed cybersecurity datasets (CIC-IDS-2017, CSE-CIC-IDS-2018, UNSW-NB15)
- **`docs/`** - Documentation files including APT testing framework guides
- **`tests/`** - Unit test modules
- **`scripts/`** - Utility scripts for verification and setup
- **`config/`** - Configuration modules
- **`logs/`** - System logs and execution traces

---

## Key Files

### Main Test Files
- **`test_comprehensive_apt_scenarios.py`** - Comprehensive APT testing framework that runs multiple APT attack scenarios (APT28, APT29, Lazarus, Silent Shadow) and tracks detection performance
- **`test_apt_final.py`** - Complete APT test with real LLM analysis, memory correlation, and autonomous response execution
- **`test_complete_agentic_system.py`** - End-to-end test of the complete agentic system workflow
- **`test_realtime_apt.py`** - Real-time APT detection testing with live network flow processing
- **`test_dataset_replay.py`** - Replay historical attack datasets through the detection system
- **`test_llm_apt_detection.py`** - Test LLM-based APT detection and reasoning capabilities
- **`test_ml_workflow.py`** - Test ML ensemble detection workflow (RF, XGBoost, DNN)
- **`test_firewall_integration.py`** - Test autonomous firewall blocking actions
- **`test_complete_response.py`** - Test complete autonomous response workflow (block + alert)

### Visualization & Analysis Scripts
- **`generate_metrics_visualizations.py`** - Generates comprehensive metrics visualizations (23+ plots) for all Agentic AI principles and APT-grouped analysis
- **`generate_consolidated_metrics_tables.py`** - Creates consolidated metrics tables (principle-level summary and APT type comparison) in CSV and formatted text
- **`calculate_system_metrics.py`** - Calculates and displays system-wide performance metrics
- **`show_current_metrics.py`** - Displays current session metrics summary

### Utility Scripts
- **`generate_architecture.py`** - Generates system architecture diagrams
- **`generate_clean_architecture.py`** - Generates clean architecture visualization
- **`generate_structure.py`** - Generates project structure documentation
- **`verify_phase3.py`** - Verifies Phase 3 implementation completeness
- **`run_apt_test.sh`** - Shell script to run APT testing suite
- **`run_memory_test.sh`** - Shell script to test memory system functionality
- **`run_routing_test.sh`** - Shell script to test routing strategy
- **`setup_phase2.sh`** - Setup script for Phase 2 components
- **`clean_memory.sh`** - Cleans memory databases and indices
- **`validate_schema.sh`** - Validates database schema integrity

### Documentation
- **`APT_TESTING_SUMMARY.md`** - Summary of APT testing framework implementation and results
- **`docs/APT_TESTING_FRAMEWORK.md`** - Detailed APT testing framework documentation

---

## Source Code Structure (`src/`)

### Core Agent (`src/agent/`)
- **`workflow_graph.py`** - LangGraph workflow definition with nodes for ML detection, LLM analysis, memory lookup, and response planning
- **`state_management.py`** - Agent state schema and management for workflow execution
- **`adaptive_learning_manager.py`** - Manages adaptive threshold learning and performance optimization
- **`feedback_manager.py`** - Handles analyst feedback incorporation and rule learning
- **`workflow_integration.py`** - Integration utilities for workflow components

### Network Detection (`src/network/`)
- **`apt_test_framework.py`** - APT test framework with scenario generation and detection tracking
- **`llm_apt_detector.py`** - LLM-based APT detection using contextual analysis and reasoning
- **`realtime_detector.py`** - Real-time network flow detection and processing
- **`dataset_replay_detector.py`** - Replay historical datasets through detection pipeline
- **`apt_campaign.py`** - APT campaign modeling with multi-stage attack simulation
- **`attack_generator.py`** - Generates synthetic attack flows for testing
- **`feature_extractor.py`** - Extracts network flow features for ML models
- **`flow_processor.py`** - Processes network flows and prepares them for analysis
- **`packet_capture.py`** - Network packet capture and flow extraction
- **`network_config.py`** - Network configuration management

### Memory System (`src/memory/`)
- **`memory_manager.py`** - Main memory manager with SQLite storage and FAISS vector search for incident correlation
- **`ip_reputation_learning.py`** - IP reputation learning system that adapts based on attack patterns
- **`models.py`** - Data models for incidents, IP reputation, and attack patterns
- **`schema_validator.py`** - Validates database schema integrity
- **`schema.sql`** - SQL schema definitions for memory database

### Metrics System (`src/metrics/`)
- **`collector.py`** - Central metrics collector that aggregates metrics from all system components into 7 Agentic AI principles
- **`storage.py`** - Metrics storage manager (SQLite database, JSON/CSV exports)
- **`models.py`** - Metrics data models for all 7 principles (Self-Learning, Contextual Awareness, Goal-Directed, Tool Utilization, Planning & Reasoning, Memory Management, Feedback Incorporation)
- **`apt_metrics.py`** - APT-specific metrics tracking and aggregation

### Actions System (`src/actions/`)
- **`action_executor.py`** - Executes autonomous response actions (block IP, send alerts)
- **`firewall_manager.py`** - Manages firewall rules and IP blocking
- **`alert_manager.py`** - Manages email alerts and notifications
- **`action_verifier.py`** - Verifies action execution success
- **`response_policies.py`** - Policy-based action selection and prioritization
- **`mock_handlers.py`** - Mock handlers for testing without actual system access

### ML Detection (`src/ml_detection/`)
- **`model_loader.py`** - Loads trained ML models (RandomForest, XGBoost, DNN) and performs ensemble predictions

### Context Analysis (`src/context/`)
- **`context_analyzer.py`** - Analyzes contextual factors (temporal, asset, user, network) for decision-making

### LLM Agent (`src/llm_agent/`)
- **`llm_client.py`** - OpenAI GPT-4 client for LLM-based threat analysis and reasoning

### Dashboard (`src/dashboard/`)
- **`live_dashboard.py`** - Real-time dashboard for monitoring system performance
- **`dashboard_components.py`** - Dashboard UI components
- **`dashboard_data_loader.py`** - Loads metrics data for dashboard visualization
- **`dashboard_realtime.py`** - Real-time data streaming for dashboard

### Utilities (`src/utils/`)
- **`colored_logger.py`** - Colored console logging utility

---

## Data Files

### Models (`models/`)
- **`rf_model_binary.pkl`**, **`xgb_model_binary.pkl`**, **`dnn_model_binary.h5`** - Trained binary classification models
- **`scaler_binary.pkl`** - Feature scaler for model input normalization
- **`label_encoder_binary.pkl`** - Label encoder for binary classification
- **`class_weights_binary.json`** - Class weights for imbalanced dataset handling
- **`*_metrics_binary.json`** - Model performance metrics
- **`*_feature_importance_binary.csv`** - Feature importance rankings

### Datasets (`datasets/`)
- **`CSE-CIC-IDS-2018-combined.csv`** - Combined CSE-CIC-IDS-2018 dataset
- **`cic-2017-collection.csv`** - CIC-IDS-2017 dataset collection
- **`ids-intrusion.csv`** - Intrusion detection dataset
- **`UNSW-NB15_master.csv`** - UNSW-NB15 master dataset

---

## Notebooks (`notebooks/`)

- **`01_dataset_unification.ipynb`** - Unifies multiple cybersecurity datasets into a single format
- **`02_feature_engineering.ipynb`** - Feature engineering and preprocessing for ML models
- **`03_model_training.ipynb`** - Trains ML ensemble models (RF, XGBoost, DNN)
- **`03_model_training_enhanced.ipynb`** - Enhanced model training with additional features
- **`04_ensemble_evaluation.ipynb`** - Evaluates ensemble model performance
- **`05_memory_system.ipynb`** - Tests and demonstrates memory system functionality
- **`06_llm_reasoning_tests.ipynb`** - Tests LLM reasoning and analysis capabilities
- **`dataset_replay.ipynb`** - Replays historical datasets through the detection system

---

## Quick Start

1. **Setup Environment**: Run `setup_phase2.sh` to initialize Phase 2 components
2. **Run APT Tests**: Execute `./run_apt_test.sh` or `python3 test_comprehensive_apt_scenarios.py`
3. **View Metrics**: Run `python3 generate_metrics_visualizations.py` to generate all visualizations
4. **Generate Tables**: Run `python3 generate_consolidated_metrics_tables.py` for consolidated metrics tables

---

## Requirements

- Use uv
- uv sync
- uv pip install .[api]
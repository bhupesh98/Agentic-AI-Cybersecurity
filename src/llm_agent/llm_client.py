"""
LLM Client for Agentic Cybersecurity System.

This module provides OpenAI integration for contextual threat analysis.
Uses langchain-openai for structured LLM interactions.

Author: Abhinav
Date: November 2025
"""

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
import os
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv

# Load .env file from project root
project_root = Path(__file__).parent.parent.parent
env_path = project_root / ".env"
load_dotenv(dotenv_path=env_path)

# LangChain imports

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Metrics integration (Week 1 Day 2)
try:
    from src.metrics import get_metrics_collector
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False
    logger.warning(
        "Metrics module not available. Metrics collection disabled.")


class CyberSecurityLLM:
    """
    LLM client for cybersecurity threat analysis.
    
    Provides contextual analysis of detected threats using OpenAI.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o-mini"):
        """
        Initialize the LLM client.
        
        Args:
            api_key: OpenAI API key. If None, reads from OPENAI_API_KEY env var
            model: OpenAI model to use (default: gpt-4o-mini for cost efficiency)
        """
        # Get API key
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")

        if not self.api_key:
            logger.warning(
                "⚠️  OPENAI_API_KEY not found. LLM analysis will be disabled.")
            self.llm = None
            return

        # Initialize ChatOpenAI
        try:
            self.llm = ChatOpenAI(
                model=model,
                temperature=0.1,  # Low temperature for consistent analysis
                api_key=self.api_key
            )
            logger.info(f"✅ LLM initialized: {model}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize LLM: {str(e)}")
            self.llm = None

    def analyze_threat(
        self,
        threat_data: Dict[str, Any],
        ml_predictions: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a detected threat with contextual awareness.
        
        Args:
            threat_data: Information about the detected threat
            ml_predictions: ML model predictions
            context: Additional context (time, user, asset, etc.)
            
        Returns:
            Dictionary containing LLM analysis and reasoning
        """
        if self.llm is None:
            return {
                "analysis": "LLM not available",
                "reasoning": "OpenAI API key not configured",
                "severity": "unknown",
                "recommended_actions": []
            }

        # Start timing for metrics (Week 1 Day 2 integration)
        start_time = datetime.utcnow()

        try:
            # Build the prompt
            system_prompt = self._build_system_prompt()
            user_prompt = self._build_threat_analysis_prompt(
                threat_data, ml_predictions, context
            )

            # Create messages
            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ]

            # Get LLM response
            response = self.llm.invoke(messages)

            # Parse response
            analysis = self._parse_llm_response(response.content)

            # Calculate latency
            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            # Record metrics (Week 1 Day 2 integration)
            if METRICS_AVAILABLE:
                try:
                    collector = get_metrics_collector()

                    # Tool utilization - LLM invocation
                    collector.record_tool_invocation(
                        'LLM', success=True, latency_ms=elapsed)

                    # Resource usage
                    collector.record_resource_usage(
                        'LLM_API_call', aligned_with_priority=True)

                except Exception:
                    pass  # Fail silently for metrics

            return analysis

        except Exception as e:
            logger.error(f"❌ LLM analysis failed: {str(e)}")

            # Record failed invocation
            if METRICS_AVAILABLE:
                try:
                    collector = get_metrics_collector()
                    elapsed = (datetime.utcnow() -
                               start_time).total_seconds() * 1000
                    collector.record_tool_invocation(
                        'LLM', success=False, latency_ms=elapsed)
                except Exception:
                    pass

            return {
                "analysis": "Error during LLM analysis",
                "reasoning": str(e),
                "severity": "unknown",
                "recommended_actions": []
            }

    def explain_detection(
        self,
        flow_data: Dict[str, Any],
        ml_prediction: Dict[str, Any]
    ) -> str:
        """
        Generate human-readable explanation of why a flow was flagged.
        
        Args:
            flow_data: Network flow information
            ml_prediction: ML model prediction details
            
        Returns:
            Human-readable explanation string
        """
        if self.llm is None:
            return "LLM not available for explanation"

        # Start timing for metrics
        start_time = datetime.utcnow()

        try:
            prompt = f"""
Given this network flow and ML prediction, explain in 2-3 sentences why this was flagged:

Network Flow:
- Source: {flow_data.get('src_ip')} : {flow_data.get('src_port')}
- Destination: {flow_data.get('dst_ip')} : {flow_data.get('dst_port')}
- Protocol: {flow_data.get('protocol')}
- Bytes: {flow_data.get('bytes_sent')} sent, {flow_data.get('bytes_received')} received

ML Prediction:
- Random Forest: {ml_prediction.get('rf_prediction')} (confidence: {ml_prediction.get('rf_confidence', 0):.2%})
- XGBoost: {ml_prediction.get('xgb_prediction')} (confidence: {ml_prediction.get('xgb_confidence', 0):.2%})
- Ensemble: {ml_prediction.get('ensemble_prediction')} (confidence: {ml_prediction.get('ensemble_confidence', 0):.2%})

Provide a clear, concise explanation for a security analyst.
"""

            response = self.llm.invoke([HumanMessage(content=prompt)])

            # Calculate latency
            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000

            # Record metrics
            if METRICS_AVAILABLE:
                try:
                    collector = get_metrics_collector()
                    collector.record_tool_invocation(
                        'LLM', success=True, latency_ms=elapsed)
                except Exception:
                    pass

            return response.content.strip()

        except Exception as e:
            logger.error(f"❌ Explanation failed: {str(e)}")

            # Record failed invocation
            if METRICS_AVAILABLE:
                try:
                    collector = get_metrics_collector()
                    elapsed = (datetime.utcnow() -
                               start_time).total_seconds() * 1000
                    collector.record_tool_invocation(
                        'LLM', success=False, latency_ms=elapsed)
                except Exception:
                    pass

            return f"Unable to generate explanation: {str(e)}"

    def _build_system_prompt(self) -> str:
        """Build the system prompt for the LLM."""
        return """You are an expert cybersecurity analyst specializing in network threat detection and incident response.

Your role is to:
1. Analyze network threats detected by ML models with contextual awareness
2. Consider factors like: time of day, user behavior, asset criticality, historical patterns
3. Provide clear, actionable analysis and recommendations
4. Explain your reasoning process transparently

Always respond in JSON format with these fields:
{
    "analysis": "Brief summary of the threat",
    "reasoning": "Step-by-step explanation of your analysis",
    "severity": "low|medium|high|critical",
    "confidence": 0.0-1.0,
    "recommended_actions": ["action1", "action2", ...],
    "context_factors": ["factor1", "factor2", ...]
}

Be concise but thorough. Focus on what matters most for incident response."""

    def _build_threat_analysis_prompt(
        self,
        threat_data: Dict[str, Any],
        ml_predictions: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Build the user prompt for threat analysis."""

        # Format ML predictions
        ml_summary = []
        for pred in ml_predictions[:3]:  # Limit to first 3 for brevity
            ml_summary.append(
                f"Flow {pred.get('flow_id', 'unknown')}: "
                f"{pred.get('ensemble_prediction', 'unknown')} "
                f"(confidence: {pred.get('ensemble_confidence', 0):.2%})"
            )

        # Format context
        context_str = "Not available"
        if context:
            context_items = []
            if 'time' in context:
                context_items.append(f"Time: {context['time']}")
            if 'business_hours' in context:
                context_items.append(
                    f"Business hours: {context['business_hours']}")
            if 'user' in context:
                context_items.append(f"User: {context['user']}")
            if 'asset_type' in context:
                context_items.append(f"Asset: {context['asset_type']}")
            context_str = ", ".join(
                context_items) if context_items else "Limited"

        prompt = f"""Analyze this detected threat:

THREAT DETAILS:
- Source IP: {threat_data.get('src_ip', 'unknown')}
- Destination IP: {threat_data.get('dst_ip', 'unknown')}
- Detected at: {threat_data.get('timestamp', datetime.utcnow().isoformat())}

ML MODEL PREDICTIONS:
{chr(10).join(ml_summary)}

CONTEXT:
{context_str}

Provide your analysis in the JSON format specified in the system prompt."""

        return prompt

    def _parse_llm_response(self, response_text: str) -> Dict[str, Any]:
        """
        Parse LLM response into structured format.
        
        Args:
            response_text: Raw LLM response
            
        Returns:
            Parsed analysis dictionary
        """
        try:
            # Try to parse as JSON
            # LLM should return JSON, but sometimes adds markdown code blocks
            text = response_text.strip()

            # Remove markdown code blocks if present
            if text.startswith("```json"):
                text = text[7:]
            if text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]

            text = text.strip()

            # Parse JSON
            parsed = json.loads(text)

            # Validate required fields
            required_fields = ['analysis', 'reasoning',
                               'severity', 'recommended_actions']
            for field in required_fields:
                if field not in parsed:
                    parsed[field] = "Not provided"

            return parsed

        except json.JSONDecodeError:
            # Fallback if JSON parsing fails
            logger.warning(
                "⚠️  Failed to parse LLM response as JSON, using raw text")
            return {
                "analysis": response_text[:200],
                "reasoning": response_text,
                "severity": "unknown",
                "confidence": 0.5,
                "recommended_actions": ["Review manually"],
                "context_factors": []
            }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

# Global LLM client instance
_global_llm = None


def get_llm_client(force_reload: bool = False) -> CyberSecurityLLM:
    """
    Get or create the global LLM client instance.
    
    Args:
        force_reload: If True, create new client even if one exists
        
    Returns:
        CyberSecurityLLM instance
    """
    global _global_llm

    if _global_llm is None or force_reload:
        _global_llm = CyberSecurityLLM()

    return _global_llm


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    """
    Test the LLM client.
    """
    print("=" * 60)
    print("Testing LLM Client")
    print("=" * 60)

    # Initialize client
    llm = CyberSecurityLLM()

    if llm.llm is None:
        print("\n❌ LLM not initialized. Check OPENAI_API_KEY environment variable.")
        print("\nTo set API key:")
        print("  export OPENAI_API_KEY='your-api-key-here'")
        print("Or add to your .env file")
    else:
        print("\n✅ LLM client initialized")

        # Test threat analysis
        print("\n🧪 Testing threat analysis...")

        test_threat = {
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.50',
            'timestamp': datetime.utcnow().isoformat()
        }

        test_predictions = [
            {
                'flow_id': 'flow-1',
                'ensemble_prediction': 'malicious',
                'ensemble_confidence': 0.95
            }
        ]

        test_context = {
            'time': '3:00 AM',
            'business_hours': False,
            'user': 'unknown',
            'asset_type': 'database_server'
        }

        try:
            analysis = llm.analyze_threat(
                test_threat, test_predictions, test_context)

            print("\n📊 LLM Analysis:")
            print(f"  Analysis: {analysis.get('analysis', 'N/A')}")
            print(f"  Severity: {analysis.get('severity', 'N/A')}")
            print(f"  Reasoning: {analysis.get('reasoning', 'N/A')[:100]}...")
            print(
                f"  Recommended Actions: {len(analysis.get('recommended_actions', []))} actions")

        except Exception as e:
            print(f"❌ Test failed: {str(e)}")

    print("\n" + "=" * 60)
    print("LLM client test complete!")
    print("=" * 60)

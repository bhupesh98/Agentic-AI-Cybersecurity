"""
Memory Management Module.

Hybrid SQLite + FAISS system for incident storage, retrieval, and correlation.

"""

from .memory_manager import MemoryManager, get_memory_manager
from .models import (
    IncidentRecord,
    IPReputation,
    SimilarIncident,
    MemoryContext,
    MemoryStats
)

from .ip_reputation_learning import (
    IPReputationLearning,
    ReputationRule
)

__all__ = [
    'MemoryManager',
    'get_memory_manager',
    'IncidentRecord',
    'IPReputation',
    'SimilarIncident',
    'MemoryContext',
    'MemoryStats',
    'IPReputationLearning',
    'ReputationRule'
]

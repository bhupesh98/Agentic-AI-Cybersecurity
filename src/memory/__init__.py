"""
Memory Management Module.

Hybrid SQLite + FAISS system for incident storage, retrieval, and correlation.

"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .memory_manager import MemoryManager, get_memory_manager
    from .models import (
        IncidentRecord,
        IPReputation,
        SimilarIncident,
        MemoryContext,
        MemoryStats,
    )
    from .ip_reputation_learning import IPReputationLearning, ReputationRule

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

_EXPORTS = {
    'MemoryManager': ('.memory_manager', 'MemoryManager'),
    'get_memory_manager': ('.memory_manager', 'get_memory_manager'),
    'IncidentRecord': ('.models', 'IncidentRecord'),
    'IPReputation': ('.models', 'IPReputation'),
    'SimilarIncident': ('.models', 'SimilarIncident'),
    'MemoryContext': ('.models', 'MemoryContext'),
    'MemoryStats': ('.models', 'MemoryStats'),
    'IPReputationLearning': ('.ip_reputation_learning', 'IPReputationLearning'),
    'ReputationRule': ('.ip_reputation_learning', 'ReputationRule'),
}


def __getattr__(name: str):
    """Lazy package exports avoid double-import warnings with ``python -m``."""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    import importlib

    module_name, attr_name = _EXPORTS[name]
    module = importlib.import_module(module_name, __name__)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value

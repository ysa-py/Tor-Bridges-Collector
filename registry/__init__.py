"""Registry package — dynamic model discovery and scoring."""
from .model_registry import ModelEntry, ModelRegistry, get_model_registry

__all__ = ["ModelRegistry", "ModelEntry", "get_model_registry"]

"""Config package — re-exports the settings singleton."""

from .settings import settings, Settings  # noqa: F401

__all__ = ["settings", "Settings"]

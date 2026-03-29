"""Model profiles for Layer 3 semantic detection.

Each profile captures model-specific behavior: prompt prefix, timeout,
confidence calibration. Adding a new model = adding a profile here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelProfile:
    """Configuration for a specific LLM model."""

    name: str
    prompt_prefix: str = ""        # prepended to user prompt (e.g. /no_think)
    timeout: int = 30              # HTTP timeout per request (seconds)
    confidence: float = 0.7        # default confidence for detected entities
    notes: str = ""


# ── Profiles registry ──

PROFILES: dict[str, ModelProfile] = {
    "qwen3:8b": ModelProfile(
        name="qwen3:8b",
        prompt_prefix="/no_think\n",
        timeout=60,
        confidence=0.75,
        notes="Best accuracy (88%), no_think for stable inference",
    ),
    "qwen3:4b": ModelProfile(
        name="qwen3:4b",
        prompt_prefix="/no_think\n",
        timeout=30,
        confidence=0.65,
        notes="Lightweight variant, untested",
    ),
    "qwen2.5:32b": ModelProfile(
        name="qwen2.5:32b",
        prompt_prefix="",
        timeout=30,
        confidence=0.7,
        notes="71% accuracy, good for high-resource environments",
    ),
    "qwen2.5:7b": ModelProfile(
        name="qwen2.5:7b",
        prompt_prefix="",
        timeout=30,
        confidence=0.65,
        notes="65% accuracy, fastest option (<1s)",
    ),
    "qwen2.5:3b": ModelProfile(
        name="qwen2.5:3b",
        prompt_prefix="",
        timeout=15,
        confidence=0.5,
        notes="35% accuracy, quick screening only",
    ),
    "internlm2:7b": ModelProfile(
        name="internlm2:7b",
        prompt_prefix="",
        timeout=30,
        confidence=0.65,
        notes="71% accuracy, good Chinese understanding",
    ),
}

# Default fallback for unknown models
_DEFAULT_PROFILE = ModelProfile(
    name="default",
    prompt_prefix="",
    timeout=30,
    confidence=0.7,
)


def get_model_profile(model: str) -> ModelProfile:
    """Get the profile for a model. Falls back to default for unknown models."""
    return PROFILES.get(model, _DEFAULT_PROFILE)

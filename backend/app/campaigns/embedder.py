"""
Multilingual semantic embedding engine for BhashaRakshak campaign clustering.

PRIMARY MODEL: paraphrase-multilingual-MiniLM-L12-v2
  - 22M parameters, 384-dimensional output
  - Supports Hindi (Devanagari + Romanized), English, and 50+ languages
  - CPU-friendly for environments without GPU

FALLBACK: When sentence-transformers / PyTorch is unavailable,
  a deterministic structural hash embedding is used. This preserves
  test determinism and allows CI to run without ML dependencies.

SECURITY:
  - Model is loaded ONCE from a fixed model name (not user-supplied paths)
  - Model artifact is never loaded from untrusted paths
  - Input is truncated before embedding to prevent memory exhaustion
  - Output dimensionality is validated before use
"""

from __future__ import annotations

import hashlib
import logging
import threading
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

EMBEDDING_DIM = 384
# Fixed model name — never allow user-supplied model paths
_MODEL_NAME = "paraphrase-multilingual-MiniLM-L12-v2"
_MAX_EMBED_CHARS = 512  # Truncate input before sending to model

# ── Model Singleton ────────────────────────────────────────────────────────────

_model = None
_model_lock = threading.Lock()
_using_mock = False
_mock_warned = False


def _load_model():
    """Load the sentence transformer model once. Thread-safe."""
    global _model, _using_mock
    with _model_lock:
        if _model is not None:
            return _model

        try:
            from sentence_transformers import SentenceTransformer
            _model = SentenceTransformer(_MODEL_NAME)
            logger.info("Loaded sentence-transformers model: %s", _MODEL_NAME)
        except Exception as exc:
            global _mock_warned
            if not _mock_warned:
                logger.warning(
                    "sentence-transformers unavailable (%s). "
                    "Using deterministic structural hash embedding (Mock Mode).",
                    exc,
                )
                _mock_warned = True
            _model = None
            _using_mock = True

    return _model


def _hash_embed(text: str, dim: int = EMBEDDING_DIM) -> np.ndarray:
    """
    Deterministic structural hash embedding for fallback mode.

    Seeds a numpy RNG from the SHA-256 digest to generate a stable,
    unit-normalized float32 vector of the requested dimension.
    Semantically similar texts will NOT cluster here — this is purely
    for structural integrity testing when torch is unavailable.
    """
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).digest()
    # Use first 4 bytes as uint32 seed for reproducibility
    seed = int.from_bytes(digest[:4], "big")
    rng = np.random.default_rng(seed)
    raw = rng.standard_normal(dim).astype(np.float32)
    norm = np.linalg.norm(raw)
    if norm < 1e-9:
        return np.zeros(dim, dtype=np.float32)
    return (raw / norm).astype(np.float32)


def validate_embedding(vec: np.ndarray) -> bool:
    """Validate that an embedding has the correct shape and is finite."""
    if vec is None:
        return False
    if not isinstance(vec, np.ndarray):
        return False
    if vec.shape != (EMBEDDING_DIM,):
        return False
    if not np.all(np.isfinite(vec)):
        return False
    return True


def embed_text(text: str) -> np.ndarray:
    """
    Embed a single text string into a 384-d unit-normalized vector.

    Args:
        text: Raw or normalized SMS text (truncated to _MAX_EMBED_CHARS).

    Returns:
        np.ndarray of shape (384,), unit-normalized float32.

    Raises:
        ValueError: If the embedding output fails dimension validation.
    """
    if not text or not text.strip():
        # Zero vector for empty input
        return np.zeros(EMBEDDING_DIM, dtype=np.float32)

    # Truncate to prevent OOM on adversarial inputs
    truncated = text[:_MAX_EMBED_CHARS]

    model = _load_model()

    if model is None or _using_mock:
        vec = _hash_embed(truncated)
    else:
        try:
            raw = model.encode(truncated, normalize_embeddings=True, show_progress_bar=False)
            vec = np.array(raw, dtype=np.float32)
        except Exception as exc:
            logger.error("Embedding failed: %s. Falling back to hash embedding.", exc)
            vec = _hash_embed(truncated)

    if not validate_embedding(vec):
        raise ValueError(
            f"Embedding validation failed: shape={getattr(vec, 'shape', None)}, "
            f"expected ({EMBEDDING_DIM},)"
        )

    return vec


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """
    Compute cosine similarity between two unit-normalized embeddings.
    Both vectors are assumed to already be unit-normalized.
    """
    if not validate_embedding(a) or not validate_embedding(b):
        return 0.0
    dot = float(np.dot(a, b))
    # Clamp to [-1, 1] to handle floating-point edge cases
    return max(-1.0, min(1.0, dot))

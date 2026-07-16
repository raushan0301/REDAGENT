"""Embedding via sentence-transformers all-MiniLM-L6-v2 (local, free, ~80MB).

Lazily loads the model so importing this module (and the RAG package) is cheap.
Embeddings are L2-normalized so cosine distance behaves well in ChromaDB.
"""

from __future__ import annotations

MODEL_NAME = "all-MiniLM-L6-v2"
_model = None


def get_embedder():
    """Load and cache the SentenceTransformer model."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer  # pip install sentence-transformers
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def embed(texts: list[str]) -> list[list[float]]:
    """Embed a batch of texts -> list of vectors (normalized)."""
    vectors = get_embedder().encode(list(texts), normalize_embeddings=True)
    return vectors.tolist()

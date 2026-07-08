"""LLM + runtime configuration, read from env / .env.

The model is a config value, NEVER hardcoded (CLAUDE.md). Free catalogs change
without warning, so provider + model name come from the environment and are
swapped by config alone. Groq is primary; Ollama is the local fallback.
"""

from __future__ import annotations

import os


# --- Primary reasoning LLM (Groq) ------------------------------------------
LLM_MODEL = os.environ.get("LLM_MODEL", "llama-3.3-70b-versatile")
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0"))

# --- Cheap lane (trivial steps: status summaries, yes/no classification) ---
CHEAP_LLM_MODEL = os.environ.get("CHEAP_LLM_MODEL", "llama-3.1-8b-instant")

# --- Local fallback (Ollama) used only when Groq 429s persist --------------
FALLBACK_LLM_MODEL = os.environ.get("FALLBACK_LLM_MODEL", "llama3.1:8b")

# --- Agent loop safety knobs (CLAUDE.md) -----------------------------------
MAX_STEPS = int(os.environ.get("REDAGENT_MAX_STEPS", "25"))
STEP_SLEEP_S = float(os.environ.get("REDAGENT_STEP_SLEEP_S", "2"))  # stay under 12K TPM


def get_llm(cheap: bool = False):
    """Return the configured chat model. Imports are local so the module loads
    even before optional deps are installed (skeleton stage)."""
    from langchain_groq import ChatGroq  # pip install langchain-groq

    model = CHEAP_LLM_MODEL if cheap else LLM_MODEL
    return ChatGroq(model=model, temperature=LLM_TEMPERATURE)  # GROQ_API_KEY from env


def get_fallback_llm():
    """Local Ollama fallback — zero API, zero rate limit."""
    from langchain_ollama import ChatOllama  # pip install langchain-ollama

    return ChatOllama(model=FALLBACK_LLM_MODEL)

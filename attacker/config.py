"""
Q-SENTINEL Attack Harness Configuration.

Centralises API target, default parameters, and experiment constants
so every attack scenario uses the same source of truth.
"""
import os

# Resolve API_URL: honour QSENTINEL_API_URL first, then infer from
# Render/Railway's dynamic $PORT, and finally fall back to 8000.
_port = os.getenv("PORT", "8000")
API_URL = os.getenv("QSENTINEL_API_URL", f"http://localhost:{_port}")
DB_PATH = os.getenv("QSENTINEL_DB_PATH", "data/ledger.db")

DEFAULT_SHOTS = int(os.getenv("QSENTINEL_DEFAULT_SHOTS", "1024"))
DEFAULT_SEED = int(os.getenv("QSENTINEL_DEFAULT_SEED", "42"))

# Channel disturbance presets — documented numerical sweep
DISTURBANCE_LEVELS = {
    "low":    0.10,
    "medium": 0.25,
    "high":   0.50,
}

# Valid-path forgery experiment — predeclared population size
FORGERY_B_POPULATION = int(os.getenv("QSENTINEL_FORGERY_B_POPULATION", "20"))

# Replay / impersonation repeat count
DEFAULT_REPEAT_COUNT = int(os.getenv("QSENTINEL_REPEAT_COUNT", "5"))

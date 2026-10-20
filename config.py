"""Configuration constants for the Employee Login Portal."""
import os

# PBKDF2-SHA256 parameters (stdlib, no external dependency).
PBKDF2_ITERATIONS = 120_000

# In-memory "database" for the demo. Structure:
#   {username: {"password_hash": ..., "created_at": ...}}
USERS_DB: dict = {}

# Session secret - use an env var in production.
SESSION_SECRET = os.environ.get("SESSION_SECRET", "change-me-in-production-abc123")

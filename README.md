# Employee Login Portal

A FastAPI application demonstrating a **Token-Bucket rate limiter** (burst 5, 5 tokens refilled every 30 s) with a complete auth flow:

1. **Signup** — create an account (passwords hashed with PBKDF2-SHA256 + salt), auto-logs the user in.
2. **Login** — authenticate with username/password, issues a signed session cookie (`itsdangerous`).
3. **Middleware (Token-Bucket)** — every request passes through a per-session token bucket.
4. **Internal pages** — `/profile` and `/dashboard`, protected (redirect to `/login` when not authenticated).
5. **Logout button** — clears the session and redirects home.

## How to run

```bash
.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
```

Open http://localhost:8000.

## How to test

```bash
.venv/bin/python -m pytest test_app.py -q    # 29 tests (unit + integration)
```

## Token-Bucket algorithm (`token_bucket.py`)

- Bucket **capacity: 5** tokens — the allowed burst size.
- **Refill: 5 tokens every 30 seconds** (discrete refill, like the reference JS implementation: `refill_amount` tokens per `refill_time` seconds) → sustained rate `refill_amount / refill_time` ≈ **0.167 req/s**.
- The window is a single constant: `TokenBucketStore(refill_time=...)` in `token_bucket.py`. Set `refill_time=1.0` for the original brief's 5 req/s (5 tokens/second), `30.0` for one burst per 30 s, `60.0` for one burst per minute.
- Each HTTP request consumes **1 token**.
- When the bucket is empty, the middleware short-circuits with **HTTP 429 Too Many Requests**.
- Implemented as Starlette middleware (`TokenBucketMiddleware` in `main.py`), so it applies to every endpoint uniformly.
- Buckets are keyed **per session**: logged-in users get a bucket per username, anonymous visitors a bucket per short-lived `anon_id` cookie. Requests with **no cookies at all** and **all auth POSTs (`POST /login`, `POST /signup`)** fall back to a **per-IP bucket** — so rotating `anon_id` values cannot bypass login rate limiting. State is in-memory in a single dict (`_buckets`) — swap for Redis in a multi-worker deployment.

You can verify 429 against a running server from a single browser session:

```
Rapid /-refreshes:   200 200 200 200 200 429 429 ...
```

A protected debug endpoint, `/api/rate-limit-status` (login required), shows the caller's
current bucket: `{"username": "...", "tokens_available": ..., "capacity": 5, "refill_amount": 5, "refill_time": 30.0, "refill_rate": 0.167, "locked": false, "retry_after": 0}`.

## Project layout

| File                | Purpose                                            |
|---------------------|----------------------------------------------------|
| `main.py`           | FastAPI app, routes, rate-limiter middleware       |
| `token_bucket.py`   | Token-bucket implementation + bucket store (discrete refill, cooldown, idle pruning) |
| `auth.py`           | PBKDF2 password hashing, session cookies           |
| `config.py`         | Config constants (PBKDF2 rounds, in-memory DB, secret) |
| `templates/`        | Jinja2 pages (index, signup, login, profile, dashboard) |
| `test_app.py`       | Unit + integration tests (29, incl. 429 behaviour)  |

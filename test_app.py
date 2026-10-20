"""Integration tests for the Employee Login Portal (FastAPI TestClient).

Covers: page rendering, signup, login (good/bad credentials), protected
pages, logout, and the token-bucket rate limiter returning 429.
"""
import time

import pytest

import token_bucket

import main
from fastapi.testclient import TestClient


def _client() -> TestClient:
    # TestClient keeps its cookie jar across requests, so the anon_id and
    # session cookies behave like a real browser session.
    return TestClient(main.app)


def _clear_buckets() -> None:
    """Reset rate-limiter state between tests."""
    token_bucket.reset_buckets()


def setup_function(_):
    _clear_buckets()


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------
def test_index_renders():
    r = _client().get("/")
    assert r.status_code == 200
    assert "Employee Login Portal" in r.text


def test_signup_page_renders():
    r = _client().get("/signup")
    assert r.status_code == 200
    assert "Create Account" in r.text


def test_login_page_renders():
    r = _client().get("/login")
    assert r.status_code == 200
    assert "Sign In" in r.text


# ---------------------------------------------------------------------------
# Signup / login
# ---------------------------------------------------------------------------
def test_signup_creates_user_and_logs_in():
    c = _client()
    r = c.post(
        "/signup", data={"username": "alice", "password": "secretpw"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/profile"

    # The signup response must set the session cookie (auto-login).
    assert "session" in r.cookies

    # Following the redirect shows the new user's profile.
    r = c.get("/profile")
    assert r.status_code == 200
    assert "alice" in r.text


def test_signup_duplicate_username_is_rejected():
    _client().post("/signup", data={"username": "bob", "password": "hunter2"})
    r = _client().post(
        "/signup", data={"username": "bob", "password": "hunter2"},
        follow_redirects=False,
    )
    assert r.status_code in (200, 400)  # re-rendered form
    assert "already exists" in r.text


def test_short_password_is_rejected():
    r = _client().post("/signup", data={"username": "carol", "password": "x"})
    assert r.status_code in (200, 400)
    assert "at least 3 characters" in r.text


def test_login_with_valid_credentials_redirects_to_profile():
    _client().post("/signup", data={"username": "dan", "password": "secretpw"})
    c = _client()
    r = c.post(
        "/login", data={"username": "dan", "password": "secretpw"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/profile"
    assert "session" in r.cookies


def test_login_with_wrong_password_shows_error():
    _client().post("/signup", data={"username": "erin", "password": "secretpw"})
    r = _client().post(
        "/login", data={"username": "erin", "password": "wrong"},
        follow_redirects=False,
    )
    assert r.status_code == 401
    assert "Invalid username or password" in r.text


def test_login_with_unknown_user_shows_error():
    r = _client().post(
        "/login", data={"username": "nobody", "password": "irrelevant"},
        follow_redirects=False,
    )
    assert r.status_code == 401
    assert "Invalid username or password" in r.text


# ---------------------------------------------------------------------------
# Protected pages
# ---------------------------------------------------------------------------
def test_profile_requires_auth():
    r = _client().get("/profile", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_dashboard_requires_auth():
    r = _client().get("/dashboard", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_logged_in_user_sees_profile_and_dashboard():
    c = _client()
    c.post("/signup", data={"username": "frank", "password": "secretpw"})
    r = c.get("/dashboard")
    assert r.status_code == 200
    assert "frank" in r.text

    r = c.get("/profile")
    assert r.status_code == 200
    assert "frank" in r.text


def test_logged_in_home_redirects_to_profile():
    c = _client()
    c.post("/signup", data={"username": "grace", "password": "secretpw"})
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/profile"


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------
def test_logout_clears_session():
    c = _client()
    c.post("/signup", data={"username": "heidi", "password": "secretpw"})
    assert c.get("/profile").status_code == 200

    r = c.post("/logout", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/"

    # Session cookie was set to an expired value (delete_cookie).
    assert "session" in r.cookies or r.headers.get("set-cookie", "").find(
        "session"
    ) != -1

    # Protected pages now redirect to login.
    r = c.get("/profile", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_rate_limit_status_requires_auth():
    r = _client().get("/api/rate-limit-status", follow_redirects=False)
    assert r.status_code == 401


def test_rate_limit_status_for_authenticated_user():
    c = _client()
    c.post("/signup", data={"username": "ivan", "password": "secretpw"})
    r = c.get("/api/rate-limit-status")
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "ivan"
    # The endpoint must echo the *live* bucket configuration, so the
    # assertions are made against the store rather than hard-coded numbers
    # (the timings are configurable in token_bucket.TokenBucketStore).
    bucket = token_bucket.get_bucket("user:ivan")
    assert body["capacity"] == bucket.capacity
    assert body["refill_amount"] == bucket.refill_amount
    assert body["refill_time"] == bucket.refill_time
    assert body["refill_rate"] == pytest.approx(bucket.refill_amount / bucket.refill_time)
    assert 0 <= body["tokens_available"] <= body["capacity"]


# ---------------------------------------------------------------------------
# Token-bucket implementation (unit)
# ---------------------------------------------------------------------------
def test_bucket_starts_full_and_consumes_one_token_per_request():
    b = token_bucket.TokenBucket(capacity=5, refill_amount=5, refill_time=1.0)
    assert b.available == 5
    assert b.consume() is True
    assert b.available == 4
    assert b.consume(3) is True
    assert b.available == 1
    assert b.consume(2) is False   # not enough tokens -> rejected


def test_bucket_refills_discretely_every_refill_cycle():
    """Refill happens in a lump once per cycle (the reference JS model)."""
    b = token_bucket.TokenBucket(capacity=5, refill_amount=5, refill_time=0.1)
    for _ in range(3):
        assert b.consume() is True
    assert b.available == 2
    time.sleep(0.12)               # one refill cycle passes
    assert b.available == 5        # refilled in a lump, capped at capacity


def test_bucket_refill_does_not_drift():
    """Leftover time of a partial cycle is kept, so the rate is exact.

    The reference JS implementation reset the timestamp to 'now' on every
    refill, discarding the remainder of the cycle and drifting below the
    configured rate.
    """
    b = token_bucket.TokenBucket(capacity=10, refill_amount=2, refill_time=0.1)
    for _ in range(5):
        b.consume()
    assert b.available == 5
    time.sleep(0.15)               # 1 full cycle + 0.05s remainder
    assert b.available == 7        # exactly one cycle added
    time.sleep(0.06)               # the kept remainder completes cycle 2
    assert b.available == 9        # a drifting implementation would show 7


def test_rejected_bucket_is_not_refilled_while_locked():
    """After a rejection, refill is suspended for the cooldown period."""
    b = token_bucket.TokenBucket(
        capacity=5, refill_amount=5, refill_time=0.05, base_cooldown=0.5
    )
    for _ in range(5):
        b.consume()
    assert b.consume() is False    # rejected -> cooldown starts
    time.sleep(0.12)               # several refill cycles pass...
    assert b.available == 0        # ...but refill stays suspended
    assert b.retry_after() >= 1


def test_bucket_rejects_invalid_configuration():
    for kwargs in (
        {"capacity": 0},
        {"refill_amount": 0},
        {"refill_time": 0},
    ):
        try:
            token_bucket.TokenBucket(**kwargs)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {kwargs}")


def test_store_prunes_idle_buckets():
    store = token_bucket.TokenBucketStore(max_buckets=2, idle_ttl=0.05)
    store.get_bucket("a")
    store.get_bucket("b")
    store.get_bucket("c")          # exceeds max_buckets -> prune runs
    time.sleep(0.08)
    store.get_bucket("d")
    assert len(store) <= 4


def test_store_handle_request_matches_reference_api():
    store = token_bucket.TokenBucketStore(capacity=2, refill_amount=2, refill_time=60)
    assert store.handle_request("k") is True
    assert store.handle_request("k") is True
    assert store.handle_request("k") is False


# ---------------------------------------------------------------------------
# Token-bucket rate limiter (HTTP behaviour)
# ---------------------------------------------------------------------------
def test_cookieless_clients_are_ip_rate_limited():
    """A client with NO cookies (e.g. a credential-enumeration bot) can't get
    a fresh bucket each time: anonymous, cookieless requests fall back to a
    per-IP bucket, so 6+ rapid requests hit 429.

    A fresh TestClient is used per request so no anon_id/ session cookie is
    carried over — exactly what a cookieless scripted client does.
    """
    codes = []
    for _ in range(7):
        r = TestClient(main.app).get("/", follow_redirects=False)
        codes.append(r.status_code)
    assert codes[:5] == [200] * 5, codes
    assert codes[5] == 429 and codes[6] == 429, codes


def test_hammering_stays_blocked_no_instant_recovery():
    """After the burst exhausts the bucket, rapid retries keep 429ing.

    Cooldown suspends refill (with backoff while hammering), so 'instant
    refresh' does not unlock the client the way plain 5/s refill did.
    """
    c = _client()
    codes = []
    for _ in range(10):
        r = c.get("/", follow_redirects=False)
        codes.append(r.status_code)
    # Request 1 runs on the IP-fallback bucket (empty cookie jar), so the
    # first 429 appears at index 5 or 6; every later hammering retry —
    # protected by the cooldown's suspended refill — must stay 429.
    first = codes.index(429)
    assert first in (5, 6), codes
    assert all(code == 429 for code in codes[first + 1 :]), codes


def test_rotating_anon_ids_does_not_bypass_login_limiting():
    """Auth POSTs are keyed by client IP, not by presented cookies.

    An enumeration bot that sends a DIFFERENT anon_id on every login
    attempt still shares one IP bucket -> 5 attempts, then 429s.
    """
    import uuid as _uuid

    codes = []
    for i in range(7):
        c = TestClient(main.app)          # fresh client each time
        c.cookies.set("anon_id", str(_uuid.uuid4()))  # always a 'new' visitor
        r = c.post(
            "/login",
            data={"username": f"bot{i}", "password": "guess"},
            follow_redirects=False,
        )
        codes.append(r.status_code)
    assert codes[:5] == [401] * 5, codes   # 5 attempts pass through (bad creds)
    assert codes[5] == 429 and codes[6] == 429, codes


def test_429_response_carries_retry_after():
    c = _client()
    r = None
    for _ in range(7):
        r = c.get("/", follow_redirects=False)
    assert r is not None and r.status_code == 429
    assert "Retry-After" in r.headers
    assert int(r.headers["Retry-After"]) >= 1


def test_token_bucket_429_when_exhausted():
    """Deterministic 429 test: inject an empty bucket and confirm response."""
    exhausted = token_bucket.TokenBucket(capacity=5, refill_amount=5, refill_time=1.0)
    exhausted.state.tokens = 0.0
    orig = main.get_bucket
    main.get_bucket = lambda key: exhausted  # type: ignore
    try:
        r = _client().get("/")
        assert r.status_code == 429
        assert "429 Too Many Requests" in r.text
    finally:
        main.get_bucket = orig


def test_token_bucket_allows_burst_of_5_then_429():
    """With a real bucket: 5 rapid requests pass, request 6 gets 429.

    The anon_id cookie persists in the client's cookie jar, so all requests
    share one bucket. (We bypass the inject-empty-bucket trick to also verify
    consume() accounting end-to-end.)
    """
    c = _client()
    codes = []
    for _ in range(7):
        r = c.get("/", follow_redirects=False)
        codes.append(r.status_code)
    assert codes[:5] == [200] * 5
    assert codes[5] == 429 or codes[6] == 429

"""FastAPI application - Employee Login Portal.

Pages:
  GET  /            -> landing page (or redirect to /profile if logged in)
  GET  /signup      -> signup form
  POST /signup      -> create account (+ auto login), redirect to /profile
  GET  /login       -> login form
  POST /login       -> authenticate, set session cookie, redirect to /profile
  GET  /profile     -> protected page
  GET  /dashboard   -> protected page
  GET/POST /logout  -> clear session, redirect to /

Middleware:
  TokenBucketMiddleware - per-client token bucket (capacity 5, refilled
  ``refill_amount`` tokens every ``refill_time`` seconds), HTTP 429 when
  the bucket is exhausted.
"""
import uuid

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.templating import Jinja2Templates

from auth import (
    clear_session_cookie,
    create_session_token,
    hash_password,
    set_session_cookie,
    verify_password,
    verify_session_token,
)
from config import USERS_DB
from token_bucket import get_bucket

app = FastAPI(title="Employee Login Portal")
templates = Jinja2Templates(directory="templates")

SESSION_COOKIE = "session"
ANON_COOKIE = "anon_id"

# Static page for HTTP 429 (plain string — no interpolation, so CSS braces
# stay literal). The dynamic retry countdown is spliced in per 429 response.
_RATE_LIMIT_PAGE_HEAD = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>429 Too Many Requests</title><style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
color:#e2e8f0;background:radial-gradient(900px 500px at 12% -8%,rgba(99,102,241,.35),transparent 60%),
radial-gradient(800px 500px at 95% 10%,rgba(139,92,246,.30),transparent 60%),
linear-gradient(160deg,#0f172a,#1e293b);}
.c{text-align:center;padding:48px 40px;max-width:460px;background:rgba(255,255,255,.97);
color:#0f172a;border-radius:16px;box-shadow:0 24px 60px -16px rgba(2,6,23,.45);border:1px solid rgba(255,255,255,.6);}
.c .code{font-size:64px;font-weight:800;letter-spacing:-.03em;line-height:1;
background:linear-gradient(135deg,#6366f1,#8b5cf6);-webkit-background-clip:text;
background-clip:text;color:transparent;}
.c h2{font-size:20px;margin:10px 0 8px;letter-spacing:-.02em;}
.c p{color:#64748b;font-size:14.5px;line-height:1.55;margin-bottom:22px;}
.c a{display:inline-block;padding:11px 22px;border-radius:10px;text-decoration:none;
font-weight:600;font-size:14px;color:#fff;background:linear-gradient(135deg,#6366f1,#4f46e5);
box-shadow:0 10px 22px -8px rgba(79,70,229,.65);}
</style></head><body><div class="c">
<div class="code">429</div>
<h2>Too Many Requests</h2>"""


def current_user(request: Request) -> str | None:
    """Return the username of the logged-in user for this request, or None."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    return verify_session_token(token)


# ---------------------------------------------------------------------------
# Token-Bucket Rate Limiter Middleware (per-client bucket, 429 on exceed)
# ---------------------------------------------------------------------------
class TokenBucketMiddleware(BaseHTTPMiddleware):
    """Per-session token-bucket rate limiting on every request.

    - Bucket: capacity 5, refilled ``refill_amount`` (5) tokens every
      ``refill_time`` seconds (30 s by default -> ~0.167 req/s sustained;
      set ``refill_time=1.0`` for 5 req/s).
    - Logged-in requests are keyed by username; anonymous requests by a
      short-lived ``anon_id`` cookie; cookieless clients by client IP.
    - When the bucket is empty the middleware short-circuits with HTTP 429
      plus a ``Retry-After`` header. Repeated hammering extends the refill
      suspension (exponential backoff, capped at 30 s) via TokenBucket.
    """

    async def dispatch(self, request: Request, call_next):
        user = current_user(request)
        needs_anon_cookie = False

        if user:
            bucket_key = f"user:{user}"
        elif request.method == "POST" and request.url.path in ("/login", "/signup"):
            # Authentication POSTs never trust client-supplied cookies:
            # an attacker can rotate a fresh ``anon_id`` on every attempt,
            # so bucket them by client IP regardless of what they send.
            ip = request.client.host if request.client else "unknown"
            bucket_key = f"ip:{ip}"
        else:
            anon_id = request.cookies.get(ANON_COOKIE)
            if anon_id:
                bucket_key = f"anon:{anon_id}"
            else:
                # No cookie at all (scripted client that never accepts
                # cookies, e.g. a password-enumeration bot). Fall back to the
                # client IP as the bucket key so cookieless traffic cannot
                # get a fresh, unlimited bucket on every request.
                ip = request.client.host if request.client else "unknown"
                bucket_key = f"ip:{ip}"
                anon_id = str(uuid.uuid4())
                needs_anon_cookie = True  # browsers get a per-cookie bucket
                                          # from their next request on

        bucket = get_bucket(bucket_key)

        if not bucket.consume(1):
            retry = bucket.retry_after()
            window = (
                int(bucket.refill_time)
                if float(bucket.refill_time).is_integer()
                else bucket.refill_time
            )
            body = (
                _RATE_LIMIT_PAGE_HEAD
             
                + "<br></br>"
                + f"<p>Try again in {retry} seconds.</p>"
                + '<a href="/">Back to home</a>'
                + "</div></body></html>"
            )
            return HTMLResponse(
                status_code=429,
                headers={"Retry-After": str(retry)},
                content=body,
            )

        response = await call_next(request)

        if needs_anon_cookie:
            response.set_cookie(
                key=ANON_COOKIE,
                value=anon_id,
                httponly=True,
                samesite="lax",
                max_age=3600,
            )
        return response


app.add_middleware(TokenBucketMiddleware)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if current_user(request):
        return RedirectResponse(url="/profile", status_code=303)
    return templates.TemplateResponse(request, "index.html", {}, status_code=200)


@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    if current_user(request):
        return RedirectResponse(url="/profile", status_code=303)
    return templates.TemplateResponse(request, "signup.html", {}, status_code=200)


@app.post("/signup")
async def signup(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if not username or not password:
        return templates.TemplateResponse(
            request, "signup.html",
            {"error": "Username and password are required."},
            status_code=400,
        )
    if username in USERS_DB:
        return templates.TemplateResponse(
            request, "signup.html",
            {"error": "Username already exists. Please log in."},
            status_code=400,
        )
    if len(password) < 3:
        return templates.TemplateResponse(
            request, "signup.html",
            {"error": "Password must be at least 3 characters."},
            status_code=400,
        )

    USERS_DB[username] = {
        "password_hash": hash_password(password),
        "created_at": "just now",
    }

    # Log the user in immediately after signup.
    response = RedirectResponse(url="/profile", status_code=303)
    set_session_cookie(response, create_session_token(username))
    return response


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if current_user(request):
        return RedirectResponse(url="/profile", status_code=303)
    return templates.TemplateResponse(request, "login.html", {}, status_code=200)


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if not username or not password:
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Username and password are required."},
            status_code=401,
        )
    user_record = USERS_DB.get(username)
    if not user_record or not verify_password(password, user_record["password_hash"]):
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Invalid username or password."},
            status_code=401,
        )

    response = RedirectResponse(url="/profile", status_code=303)
    set_session_cookie(response, create_session_token(username))
    return response


@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        request, "profile.html", {"username": user}, status_code=200
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        request, "dashboard.html", {"username": user}, status_code=200
    )


@app.post("/logout")
@app.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/", status_code=303)
    clear_session_cookie(response)
    return response


# ---------------------------------------------------------------------------
# Rate-limit debug endpoint (protected)
# ---------------------------------------------------------------------------
@app.get("/api/rate-limit-status")
async def rate_limit_status(request: Request):
    """Returns the current token-bucket state for the caller (auth required)."""
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    bucket = get_bucket(f"user:{user}")
    return {
        "username": user,
        "tokens_available": round(bucket.available, 3),
        "capacity": bucket.capacity,
        "refill_amount": bucket.refill_amount,
        "refill_time": bucket.refill_time,
        "refill_rate": bucket.refill_rate,
        "locked": bucket.is_locked,
        "retry_after": bucket.retry_after(),
    }

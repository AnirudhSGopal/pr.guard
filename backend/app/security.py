import httpx
import hmac
import hashlib
import base64
import json
import logging
import time
from app.config import settings
from urllib.parse import quote


def hash_access_token(access_token: str) -> str:
    """Return a deterministic HMAC hash for persisted token lookup."""
    if not access_token:
        return ""
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        access_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_signature(payload: bytes, signature: str) -> bool:
    """Verify GitHub webhook signature."""
    if not signature:
        return False

    expected = hmac.new(
        settings.GITHUB_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    expected_sig = f"sha256={expected}"
    return hmac.compare_digest(expected_sig, signature)


def encode_oauth_state(frontend_origin: str = "") -> str:
    payload = {
        "frontend_origin": (frontend_origin or "").strip(),
        "issued_at": int(time.time()),
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    signature = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        encoded.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{encoded}.{signature}"


def decode_oauth_state(state: str) -> dict:
    try:
        encoded, signature = (state or "").rsplit(".", 1)
        expected = hmac.new(
            settings.SECRET_KEY.encode("utf-8"),
            encoded.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return {}
        padded = encoded + ("=" * (-len(encoded) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        data = json.loads(decoded)
        issued_at = int(data.get("issued_at", 0))
        if not issued_at or abs(time.time() - issued_at) > 600:
            return {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def create_github_oauth_url(frontend_origin: str = "") -> str:
    """Generate the GitHub OAuth authorization URL."""
    # 🔗 Ensure we point back to the backend's callback URL
    # URL encode the redirect_uri to prevent it from breaking the URL structure
    if not (settings.APP_URL or "").strip():
        raise ValueError("APP_URL must be configured for GitHub OAuth callback routing.")
    redirect_uri = f"{settings.APP_URL.strip()}/auth/github/callback"
    encoded_redirect = quote(redirect_uri, safe="")
    state = quote(encode_oauth_state(frontend_origin))
    
    params = (
        f"client_id={quote(settings.GITHUB_CLIENT_ID.strip(), safe='')}"
        f"&scope=repo,read:user,user:email"
        f"&allow_signup=true"
        f"&redirect_uri={encoded_redirect}"
        f"&state={state}"
    )
    return f"https://github.com/login/oauth/authorize?{params}"


async def exchange_code_for_token(code: str) -> str | None:
    """Exchange OAuth code for a GitHub access token."""

    redirect_uri = f"{settings.APP_URL.strip()}/auth/github/callback"
    async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as client:
        resp = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={
                "Accept":     "application/json",
                "User-Agent": "PRGuard-Assistant",
            },
            json={
                "client_id":     settings.GITHUB_CLIENT_ID.strip(),
                "client_secret": settings.GITHUB_CLIENT_SECRET.strip(),
                "code":          code,
                "redirect_uri":  redirect_uri,
            },
        )

    data = resp.json()
    if resp.status_code != 200 or not data.get("access_token"):
        error = data.get("error", "unknown_error")
        description = data.get("error_description", "no description")
        logging.getLogger("prguard").warning(
            "github_token_exchange_failed status=%s error=%s description=%s",
            resp.status_code,
            error,
            description,
        )
    return data.get("access_token")


async def get_github_user(access_token: str) -> dict:
    """Fetch the authenticated GitHub user's profile."""

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept":        "application/vnd.github+json",
                "User-Agent":    "PRGuard-Assistant",
            },
        )

        if resp.status_code != 200:
            raise httpx.HTTPStatusError(
                f"GitHub /user request failed with status {resp.status_code}",
                request=resp.request,
                response=resp,
            )

        user_data = resp.json()

        # Always prefer a verified email from /user/emails for account linking.
        # The /user payload may include a public email that is not guaranteed to be verified.
        email_resp = await client.get(
            "https://api.github.com/user/emails",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept":        "application/vnd.github+json",
                "User-Agent":    "PRGuard-Assistant",
            },
        )
        if email_resp.status_code == 200:
            emails = email_resp.json()
            primary_verified = next(
                (
                    item.get("email")
                    for item in emails
                    if item.get("primary") and item.get("verified") and item.get("email")
                ),
                None,
            )
            if not primary_verified:
                primary_verified = next(
                    (item.get("email") for item in emails if item.get("verified") and item.get("email")),
                    None,
                )
            if primary_verified:
                user_data["email"] = primary_verified
                return user_data

        # Fall back to /user email only when we cannot resolve a verified address.
        if user_data.get("email"):
            return user_data

    return user_data
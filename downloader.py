import httpx
import asyncio
import json
import logging
import urllib.parse
import sys
import re
import os
import zipfile
import time
import hashlib
import shutil

# Load environment variables from .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# Set stdout encoding to UTF-8 to prevent UnicodeEncodeError on Windows
if sys.version_info >= (3, 7):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────
# Logger setup
# ─────────────────────────────────────────────────────────────────────

logger = logging.getLogger("terabridge.downloader")

if not logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
    )
    logger.addHandler(_handler)

logger.setLevel(
    os.environ.get("LOG_LEVEL", "INFO").upper()
)


# ─────────────────────────────────────────────────────────────────────
# TeraBox configuration
# ─────────────────────────────────────────────────────────────────────

BASE_PUBLIC = "https://www.terabox.com"
BASE_API = "https://dm.1024terabox.com"

# Credentials must be supplied through environment variables.
# Do not hard-code live session cookies/tokens into source code.
JSTOKEN = os.environ.get("TERABOX_JSTOKEN", "")
BDSTOKEN = os.environ.get("TERABOX_BDSTOKEN", "")
LOGID = os.environ.get("TERABOX_LOGID", "")
COOKIE = os.environ.get("TERABOX_COOKIE", "")

UA = (
    "dubox;P2SP;2.2.91.249;dubox;4.2.0.1;"
    "I2404;android-android;16;JSbridge1.0.10;"
    "jointbridge;1.1.39;"
)

ROOT_PATH = "/cloudvids"

VIDEO_EXTS = (
    ".mp4",
    ".mkv",
    ".webm",
    ".avi",
    ".mov",
    ".flv",
    ".wmv",
    ".m4v",
    ".3gp",
    ".mpg",
    ".mpeg",
    ".ts",
    ".m3u8",
)


# ─────────────────────────────────────────────────────────────────────
# Cookie helpers
# ─────────────────────────────────────────────────────────────────────

def parse_cookies(cookie_str):
    """
    Convert a Cookie header string into a dictionary.

    Example:
        ndus=abc; BAIDUID=xyz; STOKEN=123
    """
    cookies = {}

    if not cookie_str:
        return cookies

    for part in cookie_str.split(";"):
        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key:
            cookies[key] = value

    return cookies


COOKIES_DICT = parse_cookies(COOKIE)


# ─────────────────────────────────────────────────────────────────────
# HTTP headers
# ─────────────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.8",
    "Referer": f"{BASE_API}/main?category=all&path=%2F",
    "X-Requested-With": "XMLHttpRequest",
}


# ─────────────────────────────────────────────────────────────────────
# Shared HTTP session
# ─────────────────────────────────────────────────────────────────────

_session = None


def _create_session():
    """Create an httpx.AsyncClient with connection pooling."""

    pool_conn = int(
        os.environ.get("HTTP_POOL_CONNECTIONS", 50)
    )

    pool_max = int(
        os.environ.get("HTTP_POOL_MAXSIZE", 100)
    )

    limits = httpx.Limits(
        max_keepalive_connections=pool_conn,
        max_connections=pool_max,
    )

    return httpx.AsyncClient(
        headers=HEADERS,
        cookies=COOKIES_DICT,
        limits=limits,
        timeout=httpx.Timeout(30.0),
        http2=True,
        follow_redirects=True,
    )


def get_session():
    """
    Return the live shared client.
    Recreate it automatically if it has been closed.
    """

    global _session

    if _session is None or _session.is_closed:
        _session = _create_session()

    return _session


async def close_session():
    """Close the current HTTP client."""

    global _session

    if _session is not None and not _session.is_closed:
        await _session.aclose()


# ─────────────────────────────────────────────────────────────────────
# Credential management
# ─────────────────────────────────────────────────────────────────────

def update_credentials(
    cookie=None,
    js_token=None,
    bds_token=None,
    logid=None,
):
    """
    Dynamically update TeraBox credentials and session cookies.
    """

    global COOKIE
    global COOKIES_DICT
    global JSTOKEN
    global BDSTOKEN
    global LOGID

    if cookie:
        COOKIE = cookie

        COOKIES_DICT.clear()
        COOKIES_DICT.update(parse_cookies(cookie))

        client = get_session()

        try:
            client.cookies.clear()
        except Exception:
            pass

        for key, value in COOKIES_DICT.items():
            client.cookies.set(key, value)

    if js_token:
        JSTOKEN = js_token

    if bds_token:
        BDSTOKEN = bds_token

    if logid:
        LOGID = logid


# ─────────────────────────────────────────────────────────────────────
# Token extraction helpers
# ─────────────────────────────────────────────────────────────────────

def _extract_bdstoken(html):
    """
    Extract bdstoken from TeraBox HTML.

    TeraBox has used several representations over time, so don't depend
    on a single exact regex.
    """

    if not html:
        return ""

    patterns = (
        r"""["']bdstoken["']\s*:\s*["']([^"']+)["']""",
        r"""["']bdstoken["']\s*=\s*["']([^"']+)["']""",
        r"""\bbdsToken\s*[:=]\s*["']([^"']+)["']""",
        r"""\bbdstoken\s*[:=]\s*["']([^"']+)["']""",
        r"""bdstoken["']?\s*[:=]\s*["']([^"']+)["']""",
    )

    for pattern in patterns:
        match = re.search(
            pattern,
            html,
            re.IGNORECASE,
        )

        if match:
            token = match.group(1).strip()

            if token:
                return token

    return ""


def _extract_jstoken(html):
    """
    Extract and decode jsToken from TeraBox HTML.

    Returns the existing JSTOKEN if the page does not expose a usable
    replacement.
    """

    if not html:
        return JSTOKEN

    patterns = (
        r"""["']jsToken["']\s*:\s*["']([^"']+)["']""",
        r"""["']jsToken["']\s*=\s*["']([^"']+)["']""",
        r"""["']jstoken["']\s*:\s*["']([^"']+)["']""",
        r"""["']jstoken["']\s*=\s*["']([^"']+)["']""",
        r"""\bjsToken\s*=\s*["']([^"']+)["']""",
        r"""\bjstoken\s*=\s*["']([^"']+)["']""",
    )

    for pattern in patterns:
        match = re.search(
            pattern,
            html,
            re.IGNORECASE,
        )

        if not match:
            continue

        raw_value = match.group(1).strip()

        if not raw_value:
            continue

        decoded = urllib.parse.unquote(
            urllib.parse.unquote(raw_value)
        )

        # Some pages wrap the token inside fn("TOKEN")
        fn_match = re.search(
            r"""fn\s*\(\s*["']([A-Fa-f0-9]{32,})["']\s*\)""",
            decoded,
            re.IGNORECASE,
        )

        if fn_match:
            return fn_match.group(1)

        return decoded

    return JSTOKEN


def _response_is_verification_page(html):
    """Detect common TeraBox/Cloudflare verification responses."""

    if not html:
        return False

    lower_html = html.lower()

    markers = (
        "captcha",
        "verify you are human",
        "security verification",
        "cf-chl-",
        "challenge-platform",
        "访问过于频繁",
        "验证",
    )

    return any(
        marker in lower_html
        for marker in markers
    )


def _response_is_login_page(html):
    """Detect common TeraBox/Baidu login responses."""

    if not html:
        return False

    lower_html = html.lower()

    markers = (
        "passport.baidu.com",
        "account/login",
        "扫码登录",
        "login.baidu.com",
    )

    return any(
        marker in lower_html
        for marker in markers
    )


# ─────────────────────────────────────────────────────────────────────
# Log ID
# ─────────────────────────────────────────────────────────────────────

def _new_logid():
    """
    Create a request/session identifier tied to the current cookie.
    """

    seed = (
        f"{int(time.time() * 1000)}"
        f"{COOKIES_DICT.get('ndus', '')[:8]}"
    )

    return hashlib.md5(
        seed.encode()
    ).hexdigest().upper()


# ─────────────────────────────────────────────────────────────────────
# API query helper
# ─────────────────────────────────────────────────────────────────────

def qp():
    return (
        f"app_id=250528"
        f"&web=1"
        f"&channel=dubox"
        f"&clienttype=0"
        f"&jsToken={urllib.parse.quote(JSTOKEN)}"
        f"&dp-logid={urllib.parse.quote(LOGID)}"
    )


# ─────────────────────────────────────────────────────────────────────
# Validate session cookie
# ─────────────────────────────────────────────────────────────────────

async def validate_session_cookie(cookie_str):
    """
    Validate a TeraBox cookie by opening an authenticated /main page.

    Returns:
        (True, "Valid")
    or:
        (False, reason)
    """

    if not cookie_str:
        return False, "Cookie is empty"

    temp_cookies = parse_cookies(cookie_str)

    if not temp_cookies:
        return False, "Could not parse cookie string"

    browser_headers = {
        **HEADERS,
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,"
            "application/xml;q=0.9,image/avif,"
            "image/webp,*/*;q=0.8"
        ),
        "Referer": f"{BASE_PUBLIC}/",
    }

    try:
        async with httpx.AsyncClient(
            headers=browser_headers,
            cookies=temp_cookies,
            follow_redirects=True,
            timeout=20.0,
        ) as temp_client:

            response = await temp_client.get(
                f"{BASE_API}/main"
            )

            if response.status_code != 200:
                return (
                    False,
                    f"HTTP status {response.status_code}",
                )

            html = response.text

            if _response_is_verification_page(html):
                return (
                    False,
                    "TeraBox returned a verification/challenge page",
                )

            if _response_is_login_page(html):
                return (
                    False,
                    "TeraBox returned a login page",
                )

            bdstoken = _extract_bdstoken(html)

            if bdstoken:
                return True, "Valid"

            return (
                False,
                "bdstoken not found; session may be expired "
                "or TeraBox returned an unexpected page",
            )

    except httpx.HTTPError as exc:
        return (
            False,
            f"Request failed: {type(exc).__name__}",
        )

    except Exception as exc:
        return (
            False,
            f"Request failed: {exc}",
        )


# ─────────────────────────────────────────────────────────────────────
# Resolve tokens from cookie
# ─────────────────────────────────────────────────────────────────────

async def resolve_tokens_from_cookie(cookie_str):
    """
    Given a TeraBox cookie string, open the authenticated /main page
    and resolve bdstoken, jsToken and logid.

    Raises an exception if a usable authenticated page cannot be found.
    """

    if not cookie_str:
        raise ValueError(
            "TERABOX_COOKIE is empty"
        )

    temp_cookies = parse_cookies(cookie_str)

    if not temp_cookies:
        raise ValueError(
            "TERABOX_COOKIE could not be parsed"
        )

    browser_headers = {
        **HEADERS,
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,"
            "application/xml;q=0.9,image/avif,"
            "image/webp,*/*;q=0.8"
        ),
        "Referer": f"{BASE_PUBLIC}/",
    }

    diagnostics = []

    for base in (
        BASE_API,
        BASE_PUBLIC,
    ):
        try:
            async with httpx.AsyncClient(
                headers=browser_headers,
                cookies=temp_cookies,
                follow_redirects=True,
                timeout=20.0,
            ) as temp_client:

                response = await temp_client.get(
                    f"{base}/main"
                )

                if response.status_code != 200:
                    diagnostics.append(
                        f"{base}: HTTP {response.status_code}"
                    )
                    continue

                html = response.text

                if _response_is_verification_page(html):
                    diagnostics.append(
                        f"{base}: verification page returned"
                    )
                    continue

                if _response_is_login_page(html):
                    diagnostics.append(
                        f"{base}: login page returned"
                    )
                    continue

                bdstoken = _extract_bdstoken(html)
                jstoken = _extract_jstoken(html)

                if not bdstoken:
                    diagnostics.append(
                        f"{base}: bdstoken not found"
                    )
                    continue

                logid = ""

                for cookie_name, cookie_val in response.cookies.items():
                    if cookie_name.lower() == "logid":
                        logid = cookie_val
                        break

                if not logid:
                    logid = _new_logid()

                resolved = {
                    "bds_token": bdstoken,
                    "js_token": jstoken,
                    "logid": logid,
                }

                logger.info(
                    "Successfully resolved TeraBox session tokens"
                )

                return resolved

        except httpx.HTTPError as exc:
            diagnostics.append(
                f"{base}: {type(exc).__name__}"
            )

        except Exception as exc:
            diagnostics.append(
                f"{base}: {exc}"
            )

    detail = "; ".join(diagnostics)

    raise RuntimeError(
        "Failed to resolve TeraBox tokens. "
        + (
            detail
            if detail
            else "No usable authenticated response received"
        )
        + ". Check that TERABOX_COOKIE contains a current "
          "valid session cookie."
    )


# ─────────────────────────────────────────────────────────────────────
# Refresh account tokens
# ─────────────────────────────────────────────────────────────────────

async def refresh_account_tokens():
    """
    Refresh TeraBox account tokens from the authenticated main page.

    Tries both public and API hosts and detects login/verification
    responses instead of incorrectly reporting them as token failures.

    Returns:
        (bdstoken, jstoken, logid)
    """

    global JSTOKEN
    global BDSTOKEN
    global LOGID

    browser_headers = {
        **HEADERS,
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,"
            "application/xml;q=0.9,image/avif,"
            "image/webp,*/*;q=0.8"
        ),
        "Referer": f"{BASE_PUBLIC}/",
    }

    diagnostics = []

    for base in (
        BASE_API,
        BASE_PUBLIC,
    ):
        try:
            response = await get_session().get(
                f"{base}/main",
                headers=browser_headers,
                follow_redirects=True,
                timeout=25.0,
            )

            response.raise_for_status()

            html = response.text

            if _response_is_verification_page(html):
                diagnostics.append(
                    f"{base}: verification/challenge page"
                )
                continue

            if _response_is_login_page(html):
                diagnostics.append(
                    f"{base}: login page"
                )
                continue

            bdstoken = _extract_bdstoken(html)

            if not bdstoken:
                diagnostics.append(
                    f"{base}: bdstoken not found; "
                    f"HTTP {response.status_code}; "
                    f"content-type="
                    f"{response.headers.get('content-type', 'unknown')}"
                )
                continue

            jstoken = _extract_jstoken(html)

            if not jstoken:
                jstoken = JSTOKEN

            logid = ""

            for cookie_name, cookie_val in response.cookies.items():
                if cookie_name.lower() == "logid":
                    logid = cookie_val
                    break

            if not logid:
                logid = _new_logid()

            BDSTOKEN = bdstoken
            JSTOKEN = jstoken
            LOGID = logid

            logger.info(
                "Successfully extracted TeraBox session tokens from %s",
                base,
            )

            return (
                bdstoken,
                jstoken,
                logid,
            )

        except httpx.HTTPError as exc:
            diagnostics.append(
                f"{base}: request failed "
                f"({type(exc).__name__})"
            )

        except Exception as exc:
            diagnostics.append(
                f"{base}: {exc}"
            )

    detail = "; ".join(diagnostics)

    raise RuntimeError(
        "Could not extract bdstoken from TeraBox. "
        + (
            detail
            if detail
            else "No usable response received"
        )
        + ". Check that TERABOX_COOKIE contains a current, "
          "valid session cookie. If TeraBox returns a login or "
          "verification page, renew the session through the "
          "official website."
    )


# ─────────────────────────────────────────────────────────────────────
# Share session
# ─────────────────────────────────────────────────────────────────────

async def resolve_share_session(surl, link):
    """
    Get the share token required by /share/transfer.

    randsk is supplied as sekey and also stored as TSID where possible.
    """

    share_url = (
        link
        if "://" in link
        else f"https://{link}"
    )

    parsed = urllib.parse.urlparse(share_url)

    bases = [
        f"{parsed.scheme or 'https'}://{parsed.netloc}",
        BASE_PUBLIC,
        BASE_API,
    ]

    try:
        warmup = await get_session().get(
            share_url,
            headers={
                **HEADERS,
                "Referer": (
                    f"{parsed.scheme or 'https'}://"
                    f"{parsed.netloc}/"
                ),
            },
            follow_redirects=True,
            timeout=20.0,
        )

        final_base = (
            f"{warmup.url.scheme}://{warmup.url.host}"
        )

        if final_base:
            bases.insert(0, final_base)

    except httpx.HTTPError:
        pass

    seen = set()

    for base in bases:

        if not base or base in seen:
            continue

        seen.add(base)

        candidates = [
            surl,
        ]

        if not surl.startswith("1"):
            candidates.append("1" + surl)
        else:
            candidates.append(surl[1:])

        for shorturl in candidates:

            params = {
                "app_id": "250528",
                "shorturl": shorturl,
                "root": "1",
                "web": "1",
                "channel": "dubox",
                "clienttype": "0",
                "jsToken": JSTOKEN,
            }

            try:
                response = await get_session().get(
                    f"{base}/api/shorturlinfo",
                    params=params,
                    headers={
                        **HEADERS,
                        "Referer": f"{base}/",
                    },
                    follow_redirects=True,
                    timeout=20.0,
                )

                data = response.json()

            except (
                httpx.HTTPError,
                ValueError,
            ):
                continue

            if data.get("errno") == 0:

                randsk = urllib.parse.unquote(
                    data.get("randsk", "")
                )

                if randsk:

                    hostnames = [
                        parsed.hostname,
                        urllib.parse.urlparse(
                            BASE_API
                        ).hostname,
                    ]

                    for domain in hostnames:
                        if domain:
                            try:
                                get_session().cookies.set(
                                    "TSID",
                                    randsk,
                                    domain=domain,
                                    path="/",
                                )
                            except Exception:
                                pass

                return data

    return {}


# ─────────────────────────────────────────────────────────────────────
# Transfer task polling
# ─────────────────────────────────────────────────────────────────────

async def wait_for_transfer(
    task_id,
    bdstoken_val,
):
    """
    Wait until TeraBox confirms an asynchronous share copy.
    """

    for _ in range(60):

        response = await get_session().get(
            f"{BASE_API}/share/taskquery",
            params={
                "taskid": str(task_id),
                "app_id": "250528",
                "web": "1",
                "channel": "dubox",
                "clienttype": "0",
                "jsToken": JSTOKEN,
                "bdstoken": bdstoken_val,
            },
            timeout=15.0,
        )

        result = response.json()

        status = result.get("status")

        if (
            status in (2, "success")
            or (
                status == -1
                and result.get("errno") == 0
            )
        ):
            return {"errno": 0}

        if (
            status in (3, "failed")
            or result.get("errno", 0) not in (0,)
        ):
            return result

        await asyncio.sleep(2)

    return {
        "errno": -1,
        "errmsg": "Timed out waiting for TeraBox transfer",
    }


# ─────────────────────────────────────────────────────────────────────
# Transfer shared file
# ─────────────────────────────────────────────────────────────────────

async def transfer_shared_file(
    fs_id,
    share_id,
    uk,
    share_session,
    bdstoken_val,
):
    """
    Copy one shared file into ROOT_PATH.
    """

    sekey = urllib.parse.unquote(
        share_session.get("randsk", "")
    )

    profiles = [
        (
            "12",
            "terabox;1.40.0.132;PC;"
            "PC-Windows;10.0.26100;WindowsTeraBox",
        ),
        (
            "0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36",
        ),
        (
            "5",
            "Mozilla/5.0 (Linux; Android 13; SM-S918B) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Mobile Safari/537.36",
        ),
    ]

    last_result = {
        "errno": -1,
        "errmsg": "No transfer response",
    }

    for clienttype, user_agent in profiles:

        params = {
            "app_id": "250528",
            "web": "1" if clienttype == "0" else "0",
            "channel": "dubox",
            "clienttype": clienttype,
            "jsToken": JSTOKEN,
            "shareid": str(share_id),
            "from": str(uk),
            "sekey": sekey,
            "ondup": "newcopy",
            "async": "2",
            "bdstoken": bdstoken_val,
            "logid": _new_logid(),
        }

        try:
            response = await get_session().post(
                f"{BASE_API}/share/transfer",
                params=params,
                data={
                    "fsidlist": json.dumps([fs_id]),
                    "path": ROOT_PATH,
                },
                headers={
                    **HEADERS,
                    "User-Agent": user_agent,
                    "Referer": f"{BASE_API}/",
                    "Origin": BASE_API,
                    "Content-Type": (
                        "application/x-www-form-urlencoded"
                    ),
                },
                timeout=30.0,
            )

            last_result = response.json()

        except (
            httpx.HTTPError,
            ValueError,
        ) as exc:

            last_result = {
                "errno": -1,
                "errmsg": str(exc),
            }

        if last_result.get("errno") in (
            0,
            4,
            12,
        ):

            task_id = last_result.get("task_id")

            if (
                task_id
                and last_result.get("errno") == 0
            ):
                task_result = await wait_for_transfer(
                    task_id,
                    bdstoken_val,
                )

                if task_result.get("errno") != 0:
                    return task_result

            return last_result

        if last_result.get("errno") not in (
            400810,
            400141,
            -6,
        ):
            return last_result

        await asyncio.sleep(0.75)

        try:
            (
                refreshed_bdstoken,
                _,
                _,
            ) = await refresh_account_tokens()

            bdstoken_val = refreshed_bdstoken

        except Exception:
            pass

    return last_result


# ─────────────────────────────────────────────────────────────────────
# SURL parsing
# ─────────────────────────────────────────────────────────────────────

_SURL_MIN_LEN = 8

_LEADING_ONE_MAX_STRIPS = 4

_VALID_SURL = re.compile(
    r"^[A-Za-z0-9_-]+$"
)


def parse_surl(url):
    """
    Extract and clean the shorturl key from a TeraBox share link.

    Supported forms include:

      https://terabox.com/s/1ABCDEFG...
      https://1024terabox.com/s/1ABCDEFG...
      https://terabox.com/share/list?surl=1ABCDEFG...
      https://terabox.com/s/1ABCDEFG?fid=...
      1ABCDEFG...

    Returns:
        cleaned surl

    Raises:
        ValueError
    """

    if not isinstance(url, str) or not url.strip():
        raise ValueError(
            "parse_surl: empty or non-string input"
        )

    url = url.strip()

    surl = None

    # Query form
    if "surl=" in url:

        after = url.split(
            "surl=",
            1,
        )[1]

        surl = (
            after
            .split("&", 1)[0]
            .split("#", 1)[0]
        )

    # Path form
    elif "/s/" in url:

        after = url.split(
            "/s/",
            1,
        )[1]

        surl = (
            after
            .split("?", 1)[0]
            .split("#", 1)[0]
        )

    else:

        stripped = url.strip()

        if (
            "://" in stripped
            or "/" in stripped
            or "." in stripped
        ):
            raise ValueError(
                f"parse_surl: no surl marker found in {url!r}"
            )

        if stripped.startswith("http"):
            raise ValueError(
                f"parse_surl: malformed input {url!r}"
            )

        if (
            _VALID_SURL.match(stripped)
            and len(stripped) >= _SURL_MIN_LEN
        ):
            surl = stripped

    if not surl:
        raise ValueError(
            f"parse_surl: no surl found in {url!r}"
        )

    surl = (
        surl
        .rstrip("/")
        .split("/")[-1]
    )

    if not _VALID_SURL.match(surl):
        raise ValueError(
            f"parse_surl: extracted value "
            f"{surl!r} contains invalid characters"
        )

    # TeraBox sometimes uses a leading "1" in /s/ URLs.
    if len(surl) > 22 and surl.startswith("1"):

        for _ in range(
            _LEADING_ONE_MAX_STRIPS
        ):

            if (
                not surl.startswith("1")
                or len(surl) - 1 < _SURL_MIN_LEN
                or len(surl) <= 22
            ):
                break

            surl = surl[1:]

    if len(surl) < _SURL_MIN_LEN:
        raise ValueError(
            f"parse_surl: cleaned surl {surl!r} "
            f"is shorter than the "
            f"{_SURL_MIN_LEN}-char minimum"
        )

    return surl


# ─────────────────────────────────────────────────────────────────────
# Debug helper
# ─────────────────────────────────────────────────────────────────────

def show(label, r):
    print(f"\n── {label} ──")
    print(f"  Status: {r.status_code}")

    try:
        data = r.json()

        print(
            f"  {json.dumps(data, indent=2)[:800]}"
        )

        return data

    except Exception:

        print(
            f"  {r.text[:400]}"
        )

        return {}


# ─────────────────────────────────────────────────────────────────────
# Single file processing
# ─────────────────────────────────────────────────────────────────────

async def _process_single_file_metadata(
    item,
    share_id,
    uk,
    share_session,
    existing_files,
    action,
    wait_for_transcoding,
    bdstoken_val,
    quality=None,
):
    """
    Process one file from a shared link.

    Handles:
      - transfer
      - existing-file detection
      - direct-link resolution
      - HLS streaming
    """

    filename = item.get(
        "server_filename"
    )

    fs_id = item.get(
        "fs_id"
    )

    size_bytes = int(
        item.get("size", 0)
    )

    size_mb = (
        size_bytes
        / 1024
        / 1024
    )

    file_res = {
        "filename": filename,
        "size_bytes": size_bytes,
        "size_mb": round(size_mb, 2),
        "original_fs_id": fs_id,
        "fs_id": (
            fs_id
            if action == "l"
            else None
        ),
        "transfer_status": (
            "not_transferred"
            if action == "l"
            else "skipped_existing"
        ),
        "dlink": None,
        "stream_ready": False,
        "stream_m3u8": None,
        "error": None,
        "thumbnails": item.get("thumbs"),
        "path": item.get("path"),
        "is_directory": (
            str(item.get("isdir")) == "1"
        ),
    }

    if file_res["is_directory"]:
        file_res["error"] = (
            "File is a directory"
        )
        return file_res

    if action == "l":
        return file_res

    # ─────────────────────────────────────────
    # Existing-file check
    # ─────────────────────────────────────────

    my_fs_id = ""
    my_file_path = ""

    if (
        filename in existing_files
        and existing_files[filename]["size"]
        == size_bytes
    ):

        my_fs_id = existing_files[
            filename
        ]["fs_id"]

        my_file_path = existing_files[
            filename
        ]["path"]

    else:

        # ─────────────────────────────────────
        # Transfer
        # ─────────────────────────────────────

        try:

            transfer_res = (
                await transfer_shared_file(
                    fs_id,
                    share_id,
                    uk,
                    share_session,
                    bdstoken_val,
                )
            )

        except Exception as exc:

            file_res["error"] = (
                f"Transfer API request failed: {exc}"
            )

            file_res["transfer_status"] = (
                "failed"
            )

            return file_res

        # ─────────────────────────────────────
        # Create destination directory if needed
        # ─────────────────────────────────────

        if transfer_res.get("errno") == 2:

            create_url = (
                f"{BASE_API}/api/create?"
                f"{qp()}"
                f"&bdstoken={urllib.parse.quote(bdstoken_val)}"
            )

            create_payload = {
                "path": ROOT_PATH,
                "isdir": "1",
                "size": "0",
                "block_list": "[]",
                "method": "post",
            }

            try:

                cr = await get_session().post(
                    create_url,
                    data=create_payload,
                    timeout=20.0,
                )

                cr_res = cr.json()

                if cr_res.get("errno") in (
                    0,
                    -8,
                ):

                    transfer_res = (
                        await transfer_shared_file(
                            fs_id,
                            share_id,
                            uk,
                            share_session,
                            BDSTOKEN,
                        )
                    )

            except Exception as exc:

                logger.warning(
                    "Failed to auto-create directory: %s",
                    exc,
                )

        if transfer_res.get("errno") not in (
            0,
            4,
        ):

            file_res["error"] = (
                "Transfer failed with "
                f"TeraBox errno "
                f"{transfer_res.get('errno')}"
            )

            file_res["transfer_status"] = (
                "failed"
            )

            return file_res

        file_res["transfer_status"] = (
            "success"
        )

        # ─────────────────────────────────────
        # Resolve destination fs_id
        # ─────────────────────────────────────

        try:

            extra_list = (
                transfer_res
                .get("extra", {})
                .get("list", [])
            )

            if extra_list:

                my_fs_id = str(
                    extra_list[0].get(
                        "to_fs_id",
                        "",
                    )
                )

                dest_path = (
                    extra_list[0].get(
                        "to",
                        "",
                    )
                )

                if my_fs_id and dest_path:

                    filename = (
                        dest_path
                        .split("/")[-1]
                    )

                    my_file_path = (
                        dest_path
                    )

        except Exception:
            pass

        # ─────────────────────────────────────
        # Fallback search
        # ─────────────────────────────────────

        if not my_fs_id:

            encoded_dir = urllib.parse.quote(
                ROOT_PATH
            )

            try:

                r_list = await get_session().get(
                    f"{BASE_API}/api/list?"
                    f"{qp()}"
                    f"&dir={encoded_dir}"
                    f"&order=time"
                    f"&desc=1"
                    f"&showempty=0"
                    f"&page=1"
                    f"&num=20"
                    f"&bdstoken="
                    f"{urllib.parse.quote(bdstoken_val)}",
                    timeout=20.0,
                )

                list_res = r_list.json()

                for entry in list_res.get(
                    "list",
                    [],
                ):

                    entry_name = entry.get(
                        "server_filename",
                        "",
                    )

                    if (
                        filename in entry_name
                        or entry_name in filename
                    ):

                        my_fs_id = str(
                            entry.get(
                                "fs_id",
                                "",
                            )
                        )

                        filename = entry_name

                        my_file_path = (
                            entry.get(
                                "path",
                                "",
                            )
                        )

                        break

            except Exception:
                pass

    # ─────────────────────────────────────────
    # Final fs_id check
    # ─────────────────────────────────────────

    if not my_fs_id:

        file_res["error"] = (
            "Could not resolve transferred "
            "file ID in account."
        )

        return file_res

    file_res["fs_id"] = my_fs_id
    file_res["filename"] = filename
    file_res["path"] = my_file_path

    # ─────────────────────────────────────────
    # HLS streaming
    # ─────────────────────────────────────────

    is_video = bool(
        filename
        and filename.lower().endswith(
            VIDEO_EXTS
        )
    )

    if action == "s" and is_video:

        if not my_file_path:
            my_file_path = (
                ROOT_PATH.rstrip("/")
                + "/"
                + filename
            )

        encoded_path = urllib.parse.quote(
            my_file_path
        )

        if quality:

            stream_types = [
                quality
            ]

        else:

            stream_types = [
                "M3U8_AUTO_1080",
                "M3U8_AUTO_720",
                "M3U8_AUTO_480",
                "M3U8_AUTO_360",
            ]

        async def _try_stream(stype):
            """
            Try a single streaming quality.
            """

            if "1080" in stype:
                resolution = "1080p"
            elif "720" in stype:
                resolution = "720p"
            elif "480" in stype:
                resolution = "480p"
            else:
                resolution = "360p"

            url = (
                f"{BASE_API}/api/streaming?"
                f"{qp()}"
                f"&path={encoded_path}"
                f"&type={stype}"
                f"&bdstoken="
                f"{urllib.parse.quote(bdstoken_val)}"
                f"&isplayer=1"
                f"&check_blue=1"
                f"&clienttype=1"
                f"&resolution={resolution}"
            )

            try:

                sr = await get_session().get(
                    url,
                    timeout=20.0,
                )

                if (
                    sr.status_code == 200
                    and "#EXTM3U" in sr.text
                ):
                    return (
                        True,
                        0,
                        sr.text,
                    )

                err_code = None

                try:
                    res_json = sr.json()
                    err_code = res_json.get(
                        "errno"
                    )
                except Exception:
                    pass

                return (
                    False,
                    err_code,
                    sr.text[:200],
                )

            except Exception as exc:

                return (
                    False,
                    -1,
                    str(exc),
                )

        # ─────────────────────────────────────
        # Pass 1
        # ─────────────────────────────────────

        best_m3u8 = None

        all_transcoding = True

        fatal_error = None

        for stype in stream_types:

            ok, errno, text = (
                await _try_stream(stype)
            )

            if ok:

                best_m3u8 = (
                    stype,
                    text,
                )

                all_transcoding = False

                break

            elif errno == 130:

                continue

            elif errno == 31066:

                fatal_error = (
                    "File format not supported "
                    f"for streaming (errno {errno})"
                )

                all_transcoding = False

                break

            elif errno in (
                31341,
                31023,
            ):

                fatal_error = (
                    "File path error or not found "
                    f"(errno {errno})"
                )

                all_transcoding = False

                break

            else:

                all_transcoding = False

                file_res["error"] = (
                    "Streaming API errno "
                    f"{errno}: {text}"
                )

        # ─────────────────────────────────────
        # Successful stream
        # ─────────────────────────────────────

        if best_m3u8:

            file_res["stream_ready"] = True

            file_res["stream_m3u8"] = (
                best_m3u8[1]
            )

            file_res["error"] = None

        elif fatal_error:

            file_res["error"] = (
                fatal_error
            )

        # ─────────────────────────────────────
        # Wait for transcoding
        # ─────────────────────────────────────

        elif (
            all_transcoding
            and wait_for_transcoding
        ):

            max_retries = 12
            retry_delay = 10

            logger.info(
                "All resolutions still transcoding, "
                "waiting up to %ds...",
                max_retries * retry_delay,
            )

            for attempt in range(
                1,
                max_retries + 1,
            ):

                await asyncio.sleep(
                    retry_delay
                )

                for stype in stream_types:

                    ok, errno, text = (
                        await _try_stream(
                            stype
                        )
                    )

                    if ok:

                        file_res[
                            "stream_ready"
                        ] = True

                        file_res[
                            "stream_m3u8"
                        ] = text

                        file_res["error"] = None

                        break

                if file_res[
                    "stream_ready"
                ]:
                    break

            if not file_res[
                "stream_ready"
            ]:

                file_res["error"] = (
                    "transcoding_in_progress"
                )

        elif all_transcoding:

            file_res["error"] = (
                "transcoding_in_progress"
            )

    return file_res


# ─────────────────────────────────────────────────────────────────────
# Resolve link
# ─────────────────────────────────────────────────────────────────────

_resolve_lock = asyncio.Lock()


async def resolve_link(
    link,
    action="d",
    wait_for_transcoding=False,
    quality=None,
):
    """
    Resolve a TeraBox link.
    """

    return await _resolve_link(
        link,
        action,
        wait_for_transcoding,
        quality,
    )


async def _resolve_link(
    link,
    action="d",
    wait_for_transcoding=False,
    quality=None,
):
    """
    Core TeraBox resolution logic.

    Returns:
        metadata
        transfer status
        direct download links
        streaming playlists
    """

    # ─────────────────────────────────────────
    # Refresh account tokens
    # ─────────────────────────────────────────

    try:

        (
            bdstoken,
            jstoken,
            _,
        ) = await refresh_account_tokens()

        # Keep globals synchronized because qp() uses them.
        global JSTOKEN

        JSTOKEN = jstoken

    except Exception as exc:

        return {
            "errno": -1,
            "error": (
                "Failed to resolve session tokens: "
                f"{exc}"
            ),
        }

    # ─────────────────────────────────────────
    # Parse share link
    # ─────────────────────────────────────────

    try:

        surl = parse_surl(link)

    except ValueError as exc:

        return {
            "errno": -3,
            "error": (
                f"Invalid share link: {exc}"
            ),
        }

    # ─────────────────────────────────────────
    # Query share information
    # ─────────────────────────────────────────

    list_url = (
        f"{BASE_PUBLIC}/share/list"
        f"?app_id=250528"
        f"&shorturl={urllib.parse.quote(surl)}"
        f"&root=1"
        f"&order=name"
        f"&desc=0"
        f"&showempty=0"
        f"&web=1"
        f"&page=1"
        f"&num=100"
    )

    try:

        response = await get_session().get(
            list_url,
            timeout=20.0,
        )

        share_data = response.json()

    except Exception as exc:

        return {
            "errno": -2,
            "error": (
                "Failed to query share list: "
                f"{exc}"
            ),
        }

    if share_data.get("errno") != 0:

        return {
            "errno": share_data.get(
                "errno"
            ),
            "error": (
                "Share link is invalid or expired "
                f"(errno={share_data.get('errno')}, "
                f"msg={share_data.get('errmsg', 'none')}, "
                f"request_id="
                f"{share_data.get('request_id', 'none')})."
            ),
        }

    # ─────────────────────────────────────────
    # Resolve share session
    # ─────────────────────────────────────────

    share_session = (
        await resolve_share_session(
            surl,
            link,
        )
    )

    title = share_data.get(
        "title",
        "Untitled Shared Content",
    )

    share_id = share_data.get(
        "share_id"
    )

    uk = share_data.get(
        "uk"
    )

    files_list = share_data.get(
        "list",
        [],
    )

    # ─────────────────────────────────────────
    # Existing account files
    # ─────────────────────────────────────────

    existing_files = {}

    if action != "l":

        encoded_dir = urllib.parse.quote(
            ROOT_PATH
        )

        try:

            r_list = await get_session().get(
                f"{BASE_API}/api/list?"
                f"{qp()}"
                f"&dir={encoded_dir}"
                f"&order=time"
                f"&desc=1"
                f"&showempty=0"
                f"&page=1"
                f"&num=1000"
                f"&bdstoken="
                f"{urllib.parse.quote(bdstoken)}",
                timeout=20.0,
            )

            list_res = r_list.json()

            if list_res.get("errno") == 0:

                for entry in list_res.get(
                    "list",
                    [],
                ):

                    name = entry.get(
                        "server_filename"
                    )

                    existing_files[name] = {
                        "fs_id": str(
                            entry.get(
                                "fs_id",
                                "",
                            )
                        ),
                        "path": entry.get(
                            "path",
                            "",
                        ),
                        "size": int(
                            entry.get(
                                "size",
                                0,
                            )
                        ),
                        "time": int(
                            entry.get(
                                "server_mtime"
                            )
                            or entry.get(
                                "ctime"
                            )
                            or 0
                        ),
                    }

        except Exception as exc:

            logger.warning(
                "Failed to list existing account files: %s",
                exc,
            )

    # ─────────────────────────────────────────
    # Process files
    # ─────────────────────────────────────────

    results = []

    for item in files_list:

        results.append(
            await _process_single_file_metadata(
                item,
                share_id,
                uk,
                share_session,
                existing_files,
                action,
                wait_for_transcoding,
                bdstoken,
                quality,
            )
        )

    # ─────────────────────────────────────────
    # Resolve direct download links
    # ─────────────────────────────────────────

    if action != "l":

        fs_ids_to_resolve = [
            result["fs_id"]
            for result in results
            if (
                result.get("fs_id")
                and not result.get("error")
            )
        ]

        if fs_ids_to_resolve:

            chunk_size = 100

            fs_id_chunks = [
                fs_ids_to_resolve[
                    i:i + chunk_size
                ]
                for i in range(
                    0,
                    len(fs_ids_to_resolve),
                    chunk_size,
                )
            ]

            dlink_map = {}

            for chunk in fs_id_chunks:

                fsids_str = json.dumps(
                    chunk
                )

                encoded_fsids = (
                    urllib.parse.quote(
                        fsids_str
                    )
                )

                metas_url = (
                    f"{BASE_API}/api/filemetas?"
                    f"{qp()}"
                    f"&fsids={encoded_fsids}"
                    f"&dlink=1"
                    f"&thumb=0"
                    f"&bdstoken="
                    f"{urllib.parse.quote(bdstoken)}"
                )

                try:

                    mr = await get_session().get(
                        metas_url,
                        timeout=20.0,
                    )

                    metas_res = mr.json()

                    entries = metas_res.get(
                        "list",
                        metas_res.get(
                            "info",
                            [],
                        ),
                    )

                    for entry in entries:

                        entry_fs_id = str(
                            entry.get(
                                "fs_id",
                                "",
                            )
                        )

                        entry_dlink = entry.get(
                            "dlink",
                            "",
                        )

                        if (
                            entry_fs_id
                            and entry_dlink
                        ):

                            dlink_map[
                                entry_fs_id
                            ] = entry_dlink

                except Exception as exc:

                    logger.error(
                        "Batch filemetas request failed: %s",
                        exc,
                    )

            # ─────────────────────────────────
            # Attach dlinks
            # ─────────────────────────────────

            for result in results:

                if (
                    result.get("fs_id")
                    and not result.get("error")
                ):

                    my_fs_id = result[
                        "fs_id"
                    ]

                    if my_fs_id in dlink_map:

                        result["dlink"] = (
                            dlink_map[
                                my_fs_id
                            ]
                        )

                    elif action == "d":

                        result["error"] = (
                            "Failed to resolve direct "
                            "download link (dlink) from "
                            "batch filemetas."
                        )

            # ─────────────────────────────────
            # LocateDownload CDN optimization
            # ─────────────────────────────────

            async def upgrade_with_locate(result):

                path = result.get(
                    "path"
                )

                if (
                    not path
                    or result.get(
                        "is_directory"
                    )
                    or result.get(
                        "error"
                    )
                ):
                    return

                encoded_path = (
                    urllib.parse.quote(
                        path
                    )
                )

                locate_url = (
                    f"{BASE_API}/rest/2.0/pcs/file"
                    f"?ant=1"
                    f"&app_id=250528"
                    f"&channel=0"
                    f"&check_blue=1"
                    f"&clienttype=17"
                    f"&method=locatedownload"
                    f"&path={encoded_path}"
                    f"&vip=2"
                )

                try:

                    mr = await get_session().post(
                        locate_url,
                        content="",
                        timeout=15.0,
                    )

                    if mr.status_code == 200:

                        urls = mr.json().get(
                            "urls",
                            [],
                        )

                        if urls:

                            best_url = urls[
                                0
                            ].get(
                                "url"
                            )

                            if best_url:

                                result[
                                    "dlink"
                                ] = best_url

                                result[
                                    "mirrors"
                                ] = [
                                    u.get(
                                        "url"
                                    )
                                    for u in urls
                                    if u.get(
                                        "url"
                                    )
                                ]

                except Exception:
                    pass

            locate_tasks = [
                upgrade_with_locate(
                    result
                )
                for result in results
                if result.get("path")
            ]

            if locate_tasks:

                await asyncio.gather(
                    *locate_tasks
                )

    return {
        "errno": 0,
        "title": title,
        "share_id": share_id,
        "uk": uk,
        "files": results,
    }


# ─────────────────────────────────────────────────────────────────────
# Direct file downloader
# ─────────────────────────────────────────────────────────────────────

async def download_file(
    dlink,
    filename,
):
    print(
        "✅ Direct download link retrieved successfully!"
    )

    print(
        f"   Link: {dlink[:100]}..."
    )

    print(
        f"Downloading to local file: {filename} ..."
    )

    try:

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=120.0,
        ) as dl_client:

            async with dl_client.stream(
                "GET",
                dlink,
                headers={
                    "User-Agent": UA,
                    "Referer": BASE_API + "/",
                },
                cookies=COOKIES_DICT,
            ) as dr:

                content_type = dr.headers.get(
                    "Content-Type",
                    "",
                )

                content_length_header = (
                    dr.headers.get(
                        "Content-Length"
                    )
                )

                try:
                    content_length = int(
                        content_length_header
                        or 0
                    )
                except ValueError:
                    content_length = 0

                if content_length:
                    size_text = (
                        f"{content_length / 1024 / 1024:.2f} MB"
                    )
                else:
                    size_text = "unknown"

                print(
                    "  HTTP Response: "
                    f"{dr.status_code} | "
                    f"Type: {content_type} | "
                    f"Size: {size_text}"
                )

                if dr.status_code not in (
                    200,
                    206,
                ):

                    bad_body = await dr.aread()

                    print(
                        "❌ Bad download stream response: "
                        f"{bad_body[:300].decode("
                        "'utf-8', errors='ignore')}"
                    )

                    return False

                safe_filename = os.path.basename(
                    filename
                )

                if (
                    not safe_filename
                    or safe_filename in (
                        ".",
                        "..",
                    )
                ):
                    safe_filename = (
                        "downloaded_file"
                    )

                is_zip = (
                    "zip"
                    in content_type.lower()
                )

                temp_filename = (
                    safe_filename + ".zip"
                    if is_zip
                    else safe_filename
                )

                with open(
                    temp_filename,
                    "wb",
                ) as file_handle:

                    downloaded = 0

                    term_cols = (
                        shutil.get_terminal_size(
                            (80, 20)
                        ).columns
                    )

                    bar_len = min(
                        25,
                        max(
                            10,
                            term_cols - 45,
                        ),
                    )

                    tot_mb = (
                        content_length
                        / (
                            1024 * 1024
                        )
                        if content_length
                        else 0.0
                    )

                    async for chunk in dr.aiter_bytes(
                        1024 * 1024
                    ):

                        if not chunk:
                            continue

                        file_handle.write(
                            chunk
                        )

                        downloaded += len(
                            chunk
                        )

                        if content_length:

                            pct = (
                                downloaded
                                / content_length
                                * 100
                            )

                            filled = int(
                                pct
                                / 100
                                * bar_len
                            )

                            bar = (
                                "█" * filled
                                + "░"
                                * (
                                    bar_len
                                    - filled
                                )
                            )

                            dl_mb = (
                                downloaded
                                / 1024
                                / 1024
                            )

                            status_line = (
                                f"\r  [{bar}] "
                                f"{pct:5.1f}% "
                                f"{dl_mb:.1f}/"
                                f"{tot_mb:.1f} MB"
                            )

                            sys.stdout.write(
                                status_line.ljust(
                                    term_cols - 1
                                )[
                                    :term_cols - 1
                                ]
                            )

                            sys.stdout.flush()

                        else:

                            dl_mb = (
                                downloaded
                                / 1024
                                / 1024
                            )

                            status_line = (
                                f"\r  Downloaded "
                                f"{dl_mb:.1f} MB"
                            )

                            sys.stdout.write(
                                status_line
                            )

                            sys.stdout.flush()

                    if content_length:

                        sys.stdout.write(
                            "\r  ["
                            + "█" * bar_len
                            + "] 100.0% "
                            + f"{tot_mb:.1f}/"
                            + f"{tot_mb:.1f} MB\n"
                        )

                    else:

                        sys.stdout.write(
                            "\n"
                        )

                    sys.stdout.flush()

                # ─────────────────────────────
                # ZIP extraction
                # ─────────────────────────────

                if is_zip:

                    print(
                        "📦 Extracting ZIP archive..."
                    )

                    try:

                        def extract_zip():

                            dest_dir = os.path.abspath(
                                "."
                            )

                            with zipfile.ZipFile(
                                temp_filename,
                                "r",
                            ) as zf:

                                for member in (
                                    zf.infolist()
                                ):

                                    target_path = (
                                        os.path.abspath(
                                            os.path.join(
                                                dest_dir,
                                                member.filename,
                                            )
                                        )
                                    )

                                    if (
                                        not target_path.startswith(
                                            dest_dir
                                            + os.sep
                                        )
                                        and target_path
                                        != dest_dir
                                    ):

                                        raise RuntimeError(
                                            "Zip traversal "
                                            "detected: "
                                            f"{member.filename}"
                                        )

                                    zf.extract(
                                        member,
                                        dest_dir,
                                    )

                            os.remove(
                                temp_filename
                            )

                        await asyncio.to_thread(
                            extract_zip
                        )

                        print(
                            "✅ Extraction completed successfully!"
                        )

                        return True

                    except Exception as exc:

                        print(
                            f"⚠️ Error extracting ZIP: {exc}"
                        )

                        print(
                            "ZIP file kept at: "
                            f"{temp_filename}"
                        )

                        return False

                print(
                    f"✅ Successfully saved: "
                    f"{safe_filename}"
                )

                return True

    except Exception as exc:

        print(
            f"❌ Download failed: {exc}"
        )

        return False


# ─────────────────────────────────────────────────────────────────────
# CLI main
# ─────────────────────────────────────────────────────────────────────

async def main():

    global BDSTOKEN
    global JSTOKEN

    print("=" * 60)

    print(
        "        TERABOX AUTOMATIC DIRECT DOWNLOADER & STREAMER"
    )

    print("=" * 60)

    # ─────────────────────────────────────────
    # Command-line flags
    # ─────────────────────────────────────────

    stream_only = False
    list_only = False

    if "--stream" in sys.argv:

        stream_only = True

        sys.argv.remove(
            "--stream"
        )

    if "--list" in sys.argv:

        list_only = True

        sys.argv.remove(
            "--list"
        )

    # ─────────────────────────────────────────
    # Get share link
    # ─────────────────────────────────────────

    if len(sys.argv) > 1:

        link = sys.argv[1]

    else:

        link = input(
            "Enter Terabox link "
            "(or press Enter for default): "
        ).strip()

        if not link:

            link = (
                "https://terasharefile.com/"
                "s/11HTXTPgKapRLE3cTXSFMJQ"
            )

            print(
                f"Using default link: {link}"
            )

    # ─────────────────────────────────────────
    # Choose action
    # ─────────────────────────────────────────

    action = "d"

    if stream_only:

        action = "s"

    elif list_only:

        action = "l"

    else:

        choice = input(
            "\nChoose action: "
            "[D]ownload file(s), "
            "[S]tream M3U8 playlist(s), "
            "or [L]ist files? (D/S/L): "
        ).strip().lower()

        if choice == "s":

            action = "s"

        elif choice == "l":

            action = "l"

    # ─────────────────────────────────────────
    # Resolve
    # ─────────────────────────────────────────

    print(
        "Resolving Terabox link details..."
    )

    res = await resolve_link(
        link,
        action=action,
        wait_for_transcoding=True,
    )

    if res.get("errno") != 0:

        print(
            f"❌ Error: {res.get('error')}"
        )

        sys.exit(1)

    print(
        f"✅ Share Title: {res.get('title')}"
    )

    print(
        f"   Share ID   : {res.get('share_id')}"
    )

    print(
        f"   Sharer UK  : {res.get('uk')}"
    )

    print(
        f"   Files found: "
        f"{len(res.get('files', []))}"
    )

    # ─────────────────────────────────────────
    # List only
    # ─────────────────────────────────────────

    if action == "l":

        print(
            "\n── Shared Files List ──"
        )

        for i, file_info in enumerate(
            res.get("files", []),
            start=1,
        ):

            filename = file_info.get(
                "filename"
            )

            size_mb = file_info.get(
                "size_mb"
            )

            fs_id = file_info.get(
                "original_fs_id"
            )

            print(
                f"  {i}. {filename} "
                f"({size_mb} MB) "
                f"- ID: {fs_id}"
            )

        return

    # ─────────────────────────────────────────
    # Process results
    # ─────────────────────────────────────────

    for file_info in res.get(
        "files",
        [],
    ):

        filename = file_info.get(
            "filename"
        )

        size_mb = file_info.get(
            "size_mb"
        )

        print(
            f"\nPROCESSING: "
            f"{filename} ({size_mb} MB)"
        )

        if (
            file_info.get(
                "transfer_status"
            )
            == "skipped_existing"
        ):

            print(
                "ℹ️ File already exists in "
                f"{ROOT_PATH}. "
                "Skipping transfer!"
            )

        if (
            file_info.get("error")
            and file_info.get("error")
            != "transcoding_in_progress"
        ):

            print(
                f"❌ Error: "
                f"{file_info.get('error')}"
            )

            continue

        # ─────────────────────────────────────
        # Stream action
        # ─────────────────────────────────────

        if action == "s":

            if file_info.get(
                "stream_ready"
            ):

                safe_stream_filename = (
                    os.path.basename(
                        filename
                    )
                    or "stream_video"
                )

                m3u8_filename = (
                    os.path.splitext(
                        safe_stream_filename
                    )[0]
                    + ".m3u8"
                )

                with open(
                    m3u8_filename,
                    "w",
                    encoding="utf-8",
                ) as file_handle:

                    file_handle.write(
                        file_info.get(
                            "stream_m3u8",
                            "",
                        )
                    )

                print(
                    "✅ Saved M3U8 streaming "
                    f"playlist to: "
                    f"{m3u8_filename}"
                )

                print(
                    "   You can open "
                    f"{m3u8_filename} "
                    "directly in VLC or "
                    "PotPlayer to stream "
                    "the video!"
                )

            else:

                choice = input(
                    "\nStreaming playlist generation "
                    "failed (transcoding). "
                    "Would you like to "
                    "[D]ownload the raw file instead "
                    "or [E]xit/Skip? (D/E): "
                ).strip().lower()

                if choice == "d":

                    download_res = (
                        await resolve_link(
                            link,
                            action="d",
                        )
                    )

                    download_file_info = next(
                        (
                            item
                            for item in download_res.get(
                                "files",
                                [],
                            )
                            if item.get(
                                "original_fs_id"
                            )
                            == file_info.get(
                                "original_fs_id"
                            )
                        ),
                        None,
                    )

                    if (
                        download_file_info
                        and download_file_info.get(
                            "dlink"
                        )
                    ):

                        await download_file(
                            download_file_info[
                                "dlink"
                            ],
                            filename,
                        )

                continue

        # ─────────────────────────────────────
        # Download action
        # ─────────────────────────────────────

        elif action == "d":

            dlink = file_info.get(
                "dlink"
            )

            if dlink:

                await download_file(
                    dlink,
                    filename,
                )


# ─────────────────────────────────────────────────────────────────────
# Multi-connection stream generator
# ─────────────────────────────────────────────────────────────────────

async def multi_connection_stream_generator(
    dlink: str,
    start_byte: int,
    end_byte: int,
    headers: dict,
    cookies: dict,
    concurrency: int = 4,
    chunk_size: int = 2 * 1024 * 1024,
    max_ahead: int = 6,
):
    """
    Stream [start_byte, end_byte] using multiple HTTP Range requests.

    Chunks are yielded in exact sequential order while requests may
    execute concurrently.
    """

    slices = []

    current = start_byte

    index = 0

    while current <= end_byte:

        next_byte = min(
            current
            + chunk_size
            - 1,
            end_byte,
        )

        slices.append(
            (
                index,
                current,
                next_byte,
            )
        )

        current = next_byte + 1

        index += 1

    total_chunks = len(
        slices
    )

    ready_chunks = {}

    ready_events = {
        i: asyncio.Event()
        for i in range(
            total_chunks
        )
    }

    sem = asyncio.Semaphore(
        concurrency
    )

    window_sem = asyncio.Semaphore(
        max_ahead
    )

    cancelled = False

    async def worker(
        chunk_index,
        chunk_start,
        chunk_end,
        client,
    ):

        nonlocal cancelled

        if cancelled:
            return

        await window_sem.acquire()

        if cancelled:
            return

        async with sem:

            if cancelled:
                return

            request_headers = {
                **headers,
                "Range": (
                    f"bytes="
                    f"{chunk_start}-"
                    f"{chunk_end}"
                ),
            }

            for attempt in range(3):

                try:

                    response = await client.get(
                        dlink,
                        headers=request_headers,
                        timeout=60.0,
                    )

                    if response.status_code in (
                        200,
                        206,
                    ):

                        ready_chunks[
                            chunk_index
                        ] = response.content

                        ready_events[
                            chunk_index
                        ].set()

                        return

                except Exception:

                    if attempt == 2:

                        ready_chunks[
                            chunk_index
                        ] = None

                        ready_events[
                            chunk_index
                        ].set()

                        return

                    await asyncio.sleep(1)

            ready_chunks[
                chunk_index
            ] = None

            ready_events[
                chunk_index
            ].set()

    async with httpx.AsyncClient(
        cookies=cookies,
        timeout=60.0,
        limits=httpx.Limits(
            max_connections=(
                concurrency + 4
            ),
            max_keepalive_connections=(
                concurrency + 2
            ),
        ),
    ) as client:

        tasks = [
            asyncio.create_task(
                worker(
                    index,
                    start,
                    end,
                    client,
                )
            )
            for index, start, end
            in slices
        ]

        try:

            for index in range(
                total_chunks
            ):

                await ready_events[
                    index
                ].wait()

                chunk_data = (
                    ready_chunks.pop(
                        index,
                        None,
                    )
                )

                window_sem.release()

                if chunk_data is None:

                    raise IOError(
                        f"Failed to fetch chunk "
                        f"{index}"
                    )

                yield chunk_data

        except (
            asyncio.CancelledError,
            GeneratorExit,
        ):

            cancelled = True

            for task in tasks:
                task.cancel()

            raise

        finally:

            cancelled = True

            for task in tasks:

                if not task.done():
                    task.cancel()

            await asyncio.gather(
                *tasks,
                return_exceptions=True,
            )


# ─────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    async def run_cli():

        try:

            await main()

        finally:

            await close_session()

    try:

        asyncio.run(
            run_cli()
        )

    except KeyboardInterrupt:

        print(
            "\nExiting..."
        )

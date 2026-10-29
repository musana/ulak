"""
ulak - a drop-in HTTP(S) proxy hook for arbitrary Python scripts.

The name comes from the Turkish word for a courier/relay rider: a messenger
who carries dispatches from one post to the next. This library does the same
for a script's network traffic: it quietly relays every HTTP/HTTPS request the
script makes through a proxy of your choice (Burp Suite, mitmproxy, ZAP, your
own listener), without touching the script's source code.

Why
---
There is no single built-in switch that reroutes *all* outbound HTTP in a
Python process: every HTTP library opens its own socket and builds its own
connection. ``ulak`` therefore works on two layers at once:

1. It sets the standard proxy environment variables, which many clients read.
2. It monkey-patches the entry points of the well-known HTTP libraries, to
   force the proxy even on clients that ignore the environment.

Usage
-----
Add two lines at the very top of the target script::

    import ulak
    ulak.proxy("127.0.0.1", 8080)

Every request made after that line flows through 127.0.0.1:8080.

    ulak.proxy("127.0.0.1", 8080)                      # verify disabled (MITM default)
    ulak.proxy("127.0.0.1", 8080, verify=True)         # keep normal TLS verification
    ulak.proxy("127.0.0.1", 8080, verify="burp-ca.pem")# trust the proxy's CA bundle
    ulak.off()                                         # revert everything

As a context manager::

    with ulak.proxied("127.0.0.1", 8080):
        run_the_thing()

Coverage
--------
Directly patched: requests, urllib (stdlib), urllib3, httpx, aiohttp,
httplib2, niquests, curl_cffi, tornado. Covered via environment variables:
pycurl / libcurl, botocore / boto3, google-api clients, and any child process
spawned with subprocess (e.g. curl, wget) since children inherit the
environment. See README for the full matrix and the known limits.
"""

from __future__ import annotations

import logging
import os
import ssl
import sys
import warnings
from typing import Callable, Dict, List, Union

__all__ = ["proxy", "off", "proxied", "status", "is_active"]
__version__ = "0.1.0"

Verify = Union[bool, str]

logger = logging.getLogger("ulak")
logger.addHandler(logging.NullHandler())

# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

_STATE: Dict[str, object] = {
    "active": False,
    "host": None,
    "port": None,
    "url": None,
    "verify": None,     # True / False / path to a CA bundle
    "patched": [],      # libraries successfully patched
    "skipped": [],      # libraries not installed, skipped
    "unsupported": {},  # libraries present but not proxyable here (with reason)
    "errors": {},       # libraries that raised while patching
}

# Originals, kept so off() can restore them exactly.
_ORIG: Dict[str, object] = {}
_SAVED_ENV: Dict[str, Union[str, None]] = {}

_VERBOSE = True


def _banner(msg: str) -> None:
    logger.info(msg)
    if _VERBOSE:
        print(f"[ulak] {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------

_PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
              "ALL_PROXY", "all_proxy")
_NO_PROXY_ENV = ("NO_PROXY", "no_proxy")


def _set_env(proxy_url: str) -> None:
    if not _SAVED_ENV:
        for key in _PROXY_ENV + _NO_PROXY_ENV:
            _SAVED_ENV[key] = os.environ.get(key)
    for key in _PROXY_ENV:
        os.environ[key] = proxy_url
    # A NO_PROXY set by the target script would exempt some hosts; clear it so
    # that everything is routed through the proxy.
    for key in _NO_PROXY_ENV:
        os.environ.pop(key, None)


def _restore_env() -> None:
    for key, value in _SAVED_ENV.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    _SAVED_ENV.clear()


# ---------------------------------------------------------------------------
# TLS helpers
# ---------------------------------------------------------------------------

def _make_ssl_context(verify: Verify) -> ssl.SSLContext:
    """Build an SSLContext matching the requested verification policy."""
    if verify is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if isinstance(verify, str):
        return ssl.create_default_context(cafile=verify)
    return ssl.create_default_context()


def _silence_insecure_warnings() -> None:
    if _STATE["verify"] is not False:
        return
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:  # pragma: no cover - urllib3 may be absent
        pass
    try:
        from urllib3.exceptions import InsecureRequestWarning
        warnings.simplefilter("ignore", InsecureRequestWarning)
    except Exception:  # pragma: no cover
        pass


# ===========================================================================
# Patchers. Each returns True when it did something, raises ImportError when
# its library is absent, and is otherwise wrapped so a failure cannot crash
# the host script.
# ===========================================================================

def _patch_env() -> bool:
    _set_env(str(_STATE["url"]))
    return True


def _patch_ssl() -> bool:
    """Globally relax/redirect stdlib TLS verification when asked to."""
    verify = _STATE["verify"]
    if verify is True:
        return False
    _ORIG.setdefault("ssl._create_default_https_context",
                     ssl._create_default_https_context)
    if verify is False:
        ssl._create_default_https_context = ssl._create_unverified_context
    else:
        cafile = verify
        ssl._create_default_https_context = (
            lambda *a, **k: ssl.create_default_context(cafile=cafile))
    return True


def _patch_urllib() -> bool:
    import urllib.request as ur

    proxy_url = str(_STATE["url"])
    handlers: List[object] = [
        ur.ProxyHandler({"http": proxy_url, "https": proxy_url})
    ]
    if _STATE["verify"] is not True:
        handlers.append(ur.HTTPSHandler(context=_make_ssl_context(_STATE["verify"])))

    _ORIG.setdefault("urllib.opener", ur._opener)
    ur.install_opener(ur.build_opener(*handlers))
    return True


def _patch_requests() -> bool:
    import requests  # noqa: F401
    from requests.sessions import Session

    _ORIG.setdefault("requests.Session.request", Session.request)
    orig = _ORIG["requests.Session.request"]
    proxies = {"http": _STATE["url"], "https": _STATE["url"]}
    verify = _STATE["verify"]

    def request(self, method, url, **kwargs):
        kwargs["proxies"] = proxies
        kwargs["verify"] = verify
        return orig(self, method, url, **kwargs)

    Session.request = request
    _silence_insecure_warnings()
    return True


def _patch_niquests() -> bool:
    """niquests is a requests-compatible fork with its own module."""
    import niquests
    Session = niquests.Session

    _ORIG.setdefault("niquests.Session.request", Session.request)
    orig = _ORIG["niquests.Session.request"]
    proxies = {"http": _STATE["url"], "https": _STATE["url"]}
    verify = _STATE["verify"]

    def request(self, method, url, **kwargs):
        kwargs["proxies"] = proxies
        kwargs["verify"] = verify
        return orig(self, method, url, **kwargs)

    Session.request = request
    return True


def _patch_urllib3() -> bool:
    """urllib3 ignores the environment and uses its own PoolManager, so we
    swap PoolManager for a ProxyManager bound to the proxy. requests binds its
    own PoolManager reference at import time, so this does not affect it."""
    import urllib3

    proxy_url = str(_STATE["url"])
    verify = _STATE["verify"]

    _ORIG.setdefault("urllib3.PoolManager", urllib3.PoolManager)
    base_proxy_manager = urllib3.ProxyManager

    extra: Dict[str, object] = {}
    if verify is False:
        extra["cert_reqs"] = "CERT_NONE"
    elif isinstance(verify, str):
        extra["ca_certs"] = verify

    class _ProxiedPoolManager(base_proxy_manager):  # type: ignore[valid-type,misc]
        def __init__(self, num_pools=10, headers=None, **conn_kw):
            merged = dict(extra)
            merged.update(conn_kw)  # caller-supplied values win
            super().__init__(proxy_url, num_pools=num_pools,
                             headers=headers, **merged)

    urllib3.PoolManager = _ProxiedPoolManager
    _silence_insecure_warnings()
    return True


def _patch_httpx() -> bool:
    import inspect
    import httpx

    proxy_url = str(_STATE["url"])
    verify = _STATE["verify"]
    patched_any = False

    for cls_name in ("Client", "AsyncClient"):
        cls = getattr(httpx, cls_name, None)
        if cls is None:
            continue
        key = f"httpx.{cls_name}.__init__"
        _ORIG.setdefault(key, cls.__init__)
        orig_init = _ORIG[key]
        params = inspect.signature(orig_init).parameters

        def make_init(orig_init, params):
            def __init__(self, *args, **kwargs):
                # httpx renamed the argument: "proxies" (<0.26) -> "proxy".
                if "proxy" in params:
                    kwargs.setdefault("proxy", proxy_url)
                elif "proxies" in params:
                    kwargs.setdefault("proxies", proxy_url)
                if "verify" in params:
                    kwargs["verify"] = verify
                return orig_init(self, *args, **kwargs)
            return __init__

        cls.__init__ = make_init(orig_init, params)
        patched_any = True
    return patched_any


def _patch_aiohttp() -> bool:
    import aiohttp

    proxy_url = str(_STATE["url"])
    verify = _STATE["verify"]
    cls = aiohttp.ClientSession

    _ORIG.setdefault("aiohttp.ClientSession._request", cls._request)
    orig = _ORIG["aiohttp.ClientSession._request"]

    async def _request(self, method, str_or_url, **kwargs):
        kwargs.setdefault("proxy", proxy_url)
        if verify is False:
            kwargs.setdefault("ssl", False)
        elif isinstance(verify, str):
            kwargs.setdefault("ssl", _make_ssl_context(verify))
        return await orig(self, method, str_or_url, **kwargs)

    cls._request = _request
    return True


def _patch_httplib2() -> bool:
    import httplib2

    host, port = _STATE["host"], _STATE["port"]
    verify = _STATE["verify"]

    _ORIG.setdefault("httplib2.Http.__init__", httplib2.Http.__init__)
    orig = _ORIG["httplib2.Http.__init__"]
    proxy_info = httplib2.ProxyInfo(httplib2.socks.PROXY_TYPE_HTTP, host, int(port))

    def __init__(self, *args, **kwargs):
        kwargs["proxy_info"] = proxy_info
        if verify is False:
            kwargs["disable_ssl_certificate_validation"] = True
        elif isinstance(verify, str):
            kwargs["ca_certs"] = verify
        orig(self, *args, **kwargs)

    httplib2.Http.__init__ = __init__
    return True


def _patch_curl_cffi() -> bool:
    """curl_cffi exposes a requests-like API (sync Session and AsyncSession)."""
    from curl_cffi import requests as cffi

    proxies = {"http": _STATE["url"], "https": _STATE["url"]}
    verify = _STATE["verify"]
    patched_any = False

    for cls_name in ("Session", "AsyncSession"):
        cls = getattr(cffi, cls_name, None)
        if cls is None or not hasattr(cls, "request"):
            continue
        key = f"curl_cffi.{cls_name}.request"
        _ORIG.setdefault(key, cls.request)
        orig = _ORIG[key]

        def make_request(orig):
            def request(self, method, url, **kwargs):
                kwargs["proxies"] = proxies
                kwargs["verify"] = verify
                return orig(self, method, url, **kwargs)
            return request

        cls.request = make_request(orig)
        patched_any = True
    return patched_any


def _patch_tornado() -> bool:
    """Route tornado through the proxy.

    tornado's default (simple) client has no proxy support and raises if you
    pass ``proxy_host``. Only its libcurl-backed client can proxy, so we switch
    tornado to that client (requires pycurl) and inject the proxy fields into
    every HTTPRequest. Without pycurl we cannot proxy tornado without breaking
    it, so we raise NotImplementedError and leave tornado untouched.
    """
    try:
        import pycurl  # noqa: F401
    except ImportError:
        raise NotImplementedError(
            "tornado can only be proxied via its libcurl client; install "
            "pycurl to enable tornado interception")

    import tornado.httpclient as thc

    host, port = _STATE["host"], _STATE["port"]
    verify = _STATE["verify"]

    if "tornado.impl" not in _ORIG:
        _ORIG["tornado.impl"] = getattr(thc.AsyncHTTPClient, "_impl_class", None)
    thc.AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")

    _ORIG.setdefault("tornado.HTTPRequest.__init__", thc.HTTPRequest.__init__)
    orig = _ORIG["tornado.HTTPRequest.__init__"]

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("proxy_host", host)
        kwargs.setdefault("proxy_port", int(port))
        if verify is False:
            kwargs.setdefault("validate_cert", False)
        elif isinstance(verify, str):
            kwargs.setdefault("ca_certs", verify)
        orig(self, *args, **kwargs)

    thc.HTTPRequest.__init__ = __init__
    return True


# (name, patcher, restorer-key-prefix). Order matters: env and ssl first.
_PATCHERS: List[tuple] = [
    ("env", _patch_env),
    ("ssl", _patch_ssl),
    ("urllib", _patch_urllib),
    ("requests", _patch_requests),
    ("niquests", _patch_niquests),
    ("urllib3", _patch_urllib3),
    ("httpx", _patch_httpx),
    ("aiohttp", _patch_aiohttp),
    ("httplib2", _patch_httplib2),
    ("curl_cffi", _patch_curl_cffi),
    ("tornado", _patch_tornado),
]


# ---------------------------------------------------------------------------
# Restore logic (mirror of the patchers)
# ---------------------------------------------------------------------------

def _restore_all() -> None:
    if "ssl._create_default_https_context" in _ORIG:
        ssl._create_default_https_context = _ORIG.pop("ssl._create_default_https_context")

    if "urllib.opener" in _ORIG:
        import urllib.request as ur
        saved = _ORIG.pop("urllib.opener")
        if saved is None:
            ur._opener = None
        else:
            ur.install_opener(saved)

    if "requests.Session.request" in _ORIG:
        from requests.sessions import Session
        Session.request = _ORIG.pop("requests.Session.request")

    if "niquests.Session.request" in _ORIG:
        import niquests
        niquests.Session.request = _ORIG.pop("niquests.Session.request")

    if "urllib3.PoolManager" in _ORIG:
        import urllib3
        urllib3.PoolManager = _ORIG.pop("urllib3.PoolManager")

    for cls_name in ("Client", "AsyncClient"):
        key = f"httpx.{cls_name}.__init__"
        if key in _ORIG:
            import httpx
            getattr(httpx, cls_name).__init__ = _ORIG.pop(key)

    if "aiohttp.ClientSession._request" in _ORIG:
        import aiohttp
        aiohttp.ClientSession._request = _ORIG.pop("aiohttp.ClientSession._request")

    if "httplib2.Http.__init__" in _ORIG:
        import httplib2
        httplib2.Http.__init__ = _ORIG.pop("httplib2.Http.__init__")

    for cls_name in ("Session", "AsyncSession"):
        key = f"curl_cffi.{cls_name}.request"
        if key in _ORIG:
            from curl_cffi import requests as cffi
            getattr(cffi, cls_name).request = _ORIG.pop(key)

    if "tornado.HTTPRequest.__init__" in _ORIG:
        import tornado.httpclient as thc
        thc.HTTPRequest.__init__ = _ORIG.pop("tornado.HTTPRequest.__init__")
    if "tornado.impl" in _ORIG:
        import tornado.httpclient as thc
        prior = _ORIG.pop("tornado.impl")
        thc.AsyncHTTPClient.configure(prior)

    _restore_env()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def proxy(host: str = "127.0.0.1",
          port: int = 8080,
          *,
          verify: Verify = False,
          scheme: str = "http",
          verbose: bool = True) -> Dict[str, object]:
    """Route all outbound HTTP/HTTPS traffic of this process through a proxy.

    Parameters
    ----------
    host, port:
        Proxy address. Defaults to 127.0.0.1:8080 (Burp Suite's default).
    verify:
        TLS verification policy.
        ``False`` (default) disables verification, which is what an
        intercepting proxy with its own CA normally requires. ``True`` keeps
        normal verification. A string is treated as a path to a CA bundle to
        trust (export your proxy's CA and pass it here).
    scheme:
        Proxy scheme, ``"http"`` by default (Burp/ZAP/mitmproxy are HTTP
        proxies).
    verbose:
        Print a one-line activation banner to stderr.

    Calling this again re-applies with the new settings (the previous hook is
    reverted first). Returns a status dict describing what was patched.
    """
    global _VERBOSE
    _VERBOSE = verbose

    if _STATE["active"]:
        off()

    proxy_url = f"{scheme}://{host}:{port}"
    _STATE.update({
        "active": True,
        "host": host,
        "port": port,
        "url": proxy_url,
        "verify": verify,
        "patched": [],
        "skipped": [],
        "unsupported": {},
        "errors": {},
    })

    for name, fn in _PATCHERS:
        try:
            if fn():
                _STATE["patched"].append(name)  # type: ignore[union-attr]
        except ImportError:
            _STATE["skipped"].append(name)       # type: ignore[union-attr]
        except NotImplementedError as exc:
            _STATE["unsupported"][name] = str(exc)  # type: ignore[index]
        except Exception as exc:  # noqa: BLE001 - never crash the host script
            _STATE["errors"][name] = repr(exc)   # type: ignore[index]
            logger.exception("ulak: patching %s failed", name)

    _banner(f"routing HTTP/HTTPS through {proxy_url} (verify={verify!r})")
    _banner("patched: " + ", ".join(_STATE["patched"]))  # type: ignore[arg-type]
    if _STATE["unsupported"]:
        for lib, reason in _STATE["unsupported"].items():  # type: ignore[attr-defined]
            _banner(f"note: {lib} not proxied ({reason})")
    if _STATE["errors"]:
        _banner(f"errors: {_STATE['errors']}")
    if verify is False:
        _banner("WARNING: TLS verification is DISABLED; use only with a proxy you trust.")
    return status()


def off() -> None:
    """Revert every patch and restore the original environment variables."""
    if not _STATE["active"]:
        return
    try:
        _restore_all()
    finally:
        _banner("proxy disabled; all hooks reverted.")
        _STATE.update({
            "active": False, "host": None, "port": None, "url": None,
            "verify": None, "patched": [], "skipped": [],
            "unsupported": {}, "errors": {},
        })


def is_active() -> bool:
    """Return whether a proxy hook is currently installed."""
    return bool(_STATE["active"])


def status() -> Dict[str, object]:
    """Return a copy of the current state."""
    return dict(_STATE)


class proxied:
    """Context manager: proxy on inside the block, reverted on exit.

    >>> with proxied("127.0.0.1", 8080):
    ...     do_requests()
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080, **kwargs):
        self._args = (host, port)
        self._kwargs = kwargs

    def __enter__(self) -> Dict[str, object]:
        return proxy(*self._args, **self._kwargs)

    def __exit__(self, *exc) -> bool:
        off()
        return False

"""Tests for ulak.

A tiny in-process transparent proxy is started on an ephemeral port. Each
supported HTTP client is pointed at it and we assert the proxy actually saw
the connection. Clients that are not installed are skipped. Network access to
example.com is required for the live-traffic tests.
"""
import asyncio
import importlib.util
import select
import socket
import ssl
import threading

import pytest

import ulak


# --------------------------------------------------------------------------
# In-process transparent proxy (HTTP absolute-form + HTTPS CONNECT tunnel)
# --------------------------------------------------------------------------

class TunnelProxy:
    def __init__(self):
        self.seen = []
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(50)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                client, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client):
        try:
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = client.recv(4096)
                if not chunk:
                    return
                req += chunk
            method, target, _ = req.split(b"\r\n", 1)[0].decode("latin1").split(" ", 2)
            self.seen.append((method, target))
            if method == "CONNECT":
                host, port = target.split(":")
                upstream = socket.create_connection((host, int(port)))
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                self._pipe(client, upstream)
            else:
                from urllib.parse import urlparse
                u = urlparse(target)
                upstream = socket.create_connection((u.hostname, u.port or 80))
                upstream.sendall(req)
                self._pipe(client, upstream)
        except Exception:
            pass
        finally:
            client.close()

    @staticmethod
    def _pipe(a, b):
        try:
            while True:
                r, _, _ = select.select([a, b], [], [], 15)
                if not r:
                    return
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except Exception:
            pass

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


@pytest.fixture
def proxy_server():
    srv = TunnelProxy()
    yield srv
    srv.close()


@pytest.fixture
def hooked(proxy_server):
    ulak.proxy(proxy_server.host, proxy_server.port, verify=False, verbose=False)
    yield proxy_server
    ulak.off()


def _installed(name):
    return importlib.util.find_spec(name) is not None


HTTPS = "https://example.com/"
HTTP = "http://example.com/"


# --------------------------------------------------------------------------
# Live-traffic coverage, one test per client (skipped if not installed)
# --------------------------------------------------------------------------

@pytest.mark.skipif(not _installed("requests"), reason="requests not installed")
def test_requests(hooked):
    import requests
    assert requests.get(HTTPS, timeout=20).status_code == 200
    assert requests.get(HTTP, timeout=20).status_code == 200
    assert any("example.com" in t for _, t in hooked.seen)


def test_urllib(hooked):
    import urllib.request
    with urllib.request.urlopen(HTTPS, timeout=20) as r:
        assert r.status == 200
    assert hooked.seen


@pytest.mark.skipif(not _installed("urllib3"), reason="urllib3 not installed")
def test_urllib3(hooked):
    import urllib3
    assert urllib3.PoolManager().request("GET", HTTPS, timeout=20).status == 200
    assert hooked.seen


@pytest.mark.skipif(not _installed("httpx"), reason="httpx not installed")
def test_httpx(hooked):
    import httpx
    assert httpx.get(HTTPS, timeout=20).status_code == 200
    assert hooked.seen


@pytest.mark.skipif(not _installed("aiohttp"), reason="aiohttp not installed")
def test_aiohttp(hooked):
    import aiohttp

    async def go():
        async with aiohttp.ClientSession() as s:
            async with s.get(HTTPS, timeout=aiohttp.ClientTimeout(total=20)) as r:
                return r.status

    assert asyncio.run(go()) == 200
    assert hooked.seen


@pytest.mark.skipif(not _installed("niquests"), reason="niquests not installed")
def test_niquests(hooked):
    import niquests
    assert niquests.get(HTTPS, timeout=20).status_code == 200
    assert hooked.seen


@pytest.mark.skipif(not _installed("httplib2"), reason="httplib2 not installed")
def test_httplib2(hooked):
    import httplib2
    resp, _ = httplib2.Http().request(HTTPS, "GET")
    assert resp.status == 200
    assert hooked.seen


@pytest.mark.skipif(not _installed("curl_cffi"), reason="curl_cffi not installed")
def test_curl_cffi(hooked):
    from curl_cffi import requests as cffi
    assert cffi.get(HTTPS, timeout=20).status_code == 200
    assert hooked.seen


# --------------------------------------------------------------------------
# State / lifecycle
# --------------------------------------------------------------------------

def test_revert_restores_everything(proxy_server):
    import ssl as _ssl
    import urllib.request as ur

    before = {}
    if _installed("requests"):
        from requests.sessions import Session
        before["requests"] = Session.request
    if _installed("urllib3"):
        import urllib3
        before["urllib3"] = urllib3.PoolManager
    before["ssl"] = _ssl._create_default_https_context
    before["opener"] = ur._opener

    ulak.proxy(proxy_server.host, proxy_server.port, verify=False, verbose=False)
    assert ulak.is_active()
    ulak.off()
    assert not ulak.is_active()

    if "requests" in before:
        from requests.sessions import Session
        assert Session.request is before["requests"]
    if "urllib3" in before:
        import urllib3
        assert urllib3.PoolManager is before["urllib3"]
    assert _ssl._create_default_https_context is before["ssl"]
    assert ur._opener is before["opener"]


def test_double_off_is_safe():
    ulak.off()
    ulak.off()


def test_context_manager(proxy_server):
    import os
    with ulak.proxied(proxy_server.host, proxy_server.port, verbose=False):
        assert ulak.is_active()
        assert os.environ.get("HTTP_PROXY")
    assert not ulak.is_active()
    assert os.environ.get("HTTP_PROXY") is None


def test_raw_asyncio_socket_is_tunneled(proxy_server):
    """A script using loop.create_connection directly (no HTTP library) is
    only covered when raw_sockets=True."""
    import ssl as _ssl

    class _P(asyncio.Protocol):
        def __init__(self):
            self.data = bytearray()
            self.done = asyncio.get_event_loop().create_future()
            self.transport = None

        def connection_made(self, t):
            self.transport = t

        def data_received(self, d):
            self.data += d

        def connection_lost(self, exc):
            if not self.done.done():
                self.done.set_result(True)

    async def fetch():
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        loop = asyncio.get_running_loop()
        transport, proto = await loop.create_connection(
            _P, host="example.com", port=443,
            ssl=ctx, server_hostname="example.com", happy_eyeballs_delay=0.25,
        )
        transport.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n"
                        b"Connection: close\r\nAccept-Encoding: identity\r\n\r\n")
        try:
            await asyncio.wait_for(proto.done, timeout=20)
        except asyncio.TimeoutError:
            pass
        transport.close()
        return bytes(proto.data)

    ulak.proxy(proxy_server.host, proxy_server.port, verify=False,
               raw_sockets=True, verbose=False)
    try:
        data = asyncio.run(fetch())
    finally:
        ulak.off()

    assert data.split(b"\r\n", 1)[0].startswith(b"HTTP/")
    assert any(m == "CONNECT" and "example.com:443" in t for m, t in proxy_server.seen)


def test_raw_socket_detection_warns_when_off(proxy_server, capsys):
    """With raw_sockets off, a direct HTTP(S)-looking asyncio connection is not
    rerouted, but ulak warns once and points at raw_sockets=True."""
    import ssl as _ssl

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    dest_host, dest_port = srv.getsockname()

    class _P(asyncio.Protocol):
        def connection_made(self, t):
            t.close()

        def connection_lost(self, exc):
            pass

    async def go():
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await asyncio.wait_for(
                loop.create_connection(_P, dest_host, dest_port,
                                       ssl=ctx, server_hostname="x"),
                timeout=5,
            )
            transport.close()
        except Exception:
            pass  # local server is not TLS; the handshake failing is fine

    ulak.proxy(proxy_server.host, proxy_server.port, verify=False, verbose=False)
    try:
        asyncio.run(go())
    finally:
        ulak.off()
        srv.close()

    err = capsys.readouterr().err
    assert "raw_sockets=True" in err          # the actionable warning fired
    assert proxy_server.seen == []            # and it was not rerouted


def test_status_reports_patched(proxy_server):
    st = ulak.proxy(proxy_server.host, proxy_server.port, verbose=False)
    try:
        assert "env" in st["patched"]
        assert st["url"].endswith(str(proxy_server.port))
    finally:
        ulak.off()

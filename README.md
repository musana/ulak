# ulak

Send every HTTP and HTTPS request a Python script makes through your proxy, with a single import, without changing the script.

## The problem

When you run a script someone else wrote, you often want to see the HTTP traffic it sends. You can inspect it in Burp, mitmproxy, or ZAP, but getting there is painful. Either you set a system wide proxy, or you hunt down every request call in the code and add a proxy argument by hand. And Python has many HTTP libraries, so there is no single place to change.

## The solution

`ulak` does it in one line. Add it to the top of the script and all outbound traffic goes through the proxy you pick. The name is the Turkish word for a courier who carries a message from one post to the next, which is what this does for the script's requests.

```python
import ulak
ulak.proxy("127.0.0.1", 8080)
```

Every request after that line is routed through `127.0.0.1:8080`.

## Install

```bash
pip install ulak
```

There are no required dependencies. A library is only hooked if the script already uses it.

## What it covers

Hooked directly, so they go through the proxy even when they ignore the environment:

- requests
- urllib (standard library)
- urllib3
- httpx
- aiohttp
- httplib2
- niquests
- curl_cffi
- tornado (needs pycurl; without it, tornado is left alone and reported as not proxied)

Covered through the proxy environment variables that `ulak` sets:

- pycurl and libcurl
- botocore and boto3, Google API clients
- any child process started with subprocess, such as curl or wget

Covered only when you opt in with `raw_sockets=True`:

- scripts that speak HTTP over a raw asyncio socket, using their own protocol and a sans-IO parser such as h11, with no HTTP library in between. `ulak` hooks asyncio's low level `create_connection` and tunnels each connection through the proxy with an HTTP CONNECT. It is off by default because it reroutes every asyncio TCP connection in the process, which would also catch non HTTP traffic such as async database drivers.

```python
ulak.proxy("127.0.0.1", 8080, raw_sockets=True)
```

You do not have to guess when you need this. Even with `raw_sockets` off, `ulak` watches asyncio connections, and if it sees a direct HTTP or HTTPS connection slipping past the proxy it prints a one time warning telling you to re-run with `raw_sockets=True`. So the safe default stays on, and the tool tells you when to turn the option on.

## How to use

```python
import ulak

ulak.proxy("127.0.0.1", 8080)                       # verify off by default
ulak.proxy("127.0.0.1", 8080, verify=True)          # keep normal TLS checks
ulak.proxy("127.0.0.1", 8080, verify="burp-ca.pem") # trust your proxy's CA
ulak.off()                                          # undo everything
```

Only for one block of code:

```python
with ulak.proxied("127.0.0.1", 8080):
    run_the_thing()
```

Check the current state:

```python
ulak.status()     # what was patched, skipped, or failed
ulak.is_active()  # True or False
```

## A note on TLS

A proxy like Burp breaks into TLS with its own certificate authority, which your client does not trust. That is why `verify` is off by default, so HTTPS requests do not fail. This turns off certificate checking, so use it only with a local proxy you control. The cleaner way is to export your proxy's CA certificate and pass `verify="path/to/ca.pem"`, which keeps verification on and trusts the proxy.

## Limits

`ulak` works at the library level, so by default it cannot catch traffic that skips those libraries, such as libraries that carry their own TLS stack in C. For raw asyncio sockets there is the `raw_sockets=True` option described above. When you call `ulak.off()`, every change is reverted and the environment is restored to how it was.

One honest note on the startup banner. It lists the HTTP libraries that are installed in the process and got hooked, not the ones your specific script actually uses. If your script talks over raw sockets and uses none of those libraries, the banner can still list several of them because they happen to be installed. In that case the traffic is not proxied unless you turn on `raw_sockets=True`, and the live detector described above will point that out when it happens.

## License

MIT

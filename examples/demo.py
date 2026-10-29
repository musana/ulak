"""Minimal demo: import ulak, point it at your proxy, make requests.

Run Burp/mitmproxy on 127.0.0.1:8080, then:  python examples/demo.py
"""
import ulak

# One line. Everything below goes through the proxy.
ulak.proxy("127.0.0.1", 8080)          # verify=False by default (for MITM CAs)

import requests
print(requests.get("https://example.com/").status_code)

# Turn it off when you no longer want interception.
ulak.off()

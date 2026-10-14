import http.client
import json
import socket
import ssl
import time
from urllib.parse import urlsplit, urlunsplit

MAX_BODY = 65536
HDR = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "content-security-policy-report-only": "CSP-Report-Only",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-resource-policy": "CORP",
    "server": "Server",
    "set-cookie": "Set-Cookie",
}
WANT = ("content-security-policy", "x-frame-options",
        "x-content-type-options", "referrer-policy")
LEAK = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-runtime")


def vso_norm(url, dflt_scheme="https"):
    u = url.strip()
    if "://" not in u:
        u = f"{dflt_scheme}://{u}"
    p = urlsplit(u)
    if p.scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")
    if not p.hostname:
        raise ValueError("missing host")
    if p.username or p.password or "@" in p.netloc:
        raise ValueError("userinfo in url rejected")
    if p.port and not (0 < p.port < 65536):
        raise ValueError("invalid port")
    path = p.path or "/"
    return urlunsplit((p.scheme, p.netloc, path, p.query, ""))


def vso_fetch(url, cfg, method="GET", hdrs=None):
    p = urlsplit(url)
    out = {"url": url, "ok": False, "err": None, "status": None,
           "ms": 0.0, "hdr": {}, "body_len": None, "chain_ok": None, "ver": None}
    hdrs = hdrs or {}
    conn = None
    t0 = time.perf_counter()
    try:
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(p.hostname, p.port, timeout=cfg.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(p.hostname, p.port, timeout=cfg.timeout)
        path = p.path or "/"
        if p.query:
            path = f"{path}?{p.query}"
        conn.request(method, path, headers={"host": p.netloc, "user-agent": "netprobe/1.0",
                                           "accept": "*/*", "connection": "close", **hdrs})
        r = conn.getresponse()
        body = r.read(MAX_BODY)
        out["ok"] = True
        out["status"] = r.status
        out["hdr"] = {k.lower(): v for k, v in r.getheaders()}
        out["body_len"] = len(body)
        out["ms"] = round((time.perf_counter() - t0) * 1000, 2)
        if p.scheme == "https":
            out["ver"] = conn.sock.version() if conn.sock else None
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as e:
        out["err"] = f"{type(e).__name__}"
    finally:
        if conn:
            try:
                conn.close()
            except OSError:
                pass
    return out


def inf_chain(url, cfg):
    p = urlsplit(url)
    if p.scheme != "https":
        return None
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((p.hostname, p.port or 443), timeout=cfg.timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=p.hostname):
                return True
    except ssl.SSLCertVerificationError:
        return False
    except (ssl.SSLError, OSError):
        return None


def inf_grade(res, tls, url):
    f = []
    h = res.get("hdr", {})
    if not res.get("ok"):
        return ["unreachable"], "F", 0
    if res.get("status", 0) >= 500:
        f.append("server-5xx")
    is_https = urlsplit(url).scheme == "https"
    for k in WANT:
        if k not in h:
            f.append(f"missing:{HDR[k]}")
    if is_https:
        if "strict-transport-security" not in h:
            f.append("missing:HSTS")
        sc = h.get("set-cookie", "")
        if sc and "secure" not in sc.lower():
            f.append("cookie-no-secure")
    else:
        f.append("plaintext-http")
    for k in LEAK:
        if k in h:
            f.append(f"disclosure:{HDR.get(k, k)}")
    if tls:
        if tls.get("expired"):
            f.append("cert-expired")
        elif tls.get("days") is not None and tls["days"] < 15:
            f.append("cert-expiring")
        if tls.get("chain_ok") is False:
            f.append("cert-chain-untrusted")
        if tls.get("ver") in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            f.append(f"weak-tls:{tls['ver']}")
        if not tls.get("san"):
            f.append("cert-no-san")
    w = 100
    w -= min(60, 12 * len([x for x in f if not x.startswith("disclosure")]))
    w -= 20 if "plaintext-http" in f else 0
    w -= 25 if tls and tls.get("chain_ok") is False else 0
    if w < 0:
        w = 0
    grade = "A" if w >= 90 else "B" if w >= 75 else "C" if w >= 60 else "D" if w >= 40 else "F"
    return f, grade, w


def inf_render(res, tls, url):
    f, g, w = inf_grade(res, tls, url)
    lines = [f"URL      {url}", f"grade    {g} ({w}/100)"]
    if res.get("err"):
        lines.append(f"error    {res['err']}")
    if res.get("ok"):
        lines.append(f"status   {res['status']}  {res['ms']}ms  {res['body_len']}B")
    if tls and tls.get("ok"):
        lines.append(f"tls      {tls.get('ver')} {tls.get('cipher')} alpn={tls.get('alpn')}")
        lines.append(f"cert     issuer={tls.get('issuer')}")
        lines.append(f"expiry   {tls.get('not_after')} ({tls.get('days')}d) chain={tls.get('chain_ok')}")
    for x in f:
        lines.append(f"  [!] {x}")
    return "\n".join(lines)


def inf_json(res, tls, url):
    f, g, w = inf_grade(res, tls, url)
    return json.dumps({"url": url, "grade": g, "score": w, "findings": f,
                       "result": res, "tls": tls}, indent=2, default=str)

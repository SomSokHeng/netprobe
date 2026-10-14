import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone

try:
    from cryptography import x509
except ImportError:
    x509 = None

TIMEOUT = 5.0
RETRY = 2
RATE = 0.15
WEAK_VER = ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3")


class Err(Exception):
    pass


def vso_cfg_host(tgt):
    h = tgt.strip()
    if not h or any(c.isspace() for c in h):
        raise Err("invalid host")
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0].split("?", 1)[0]
    if "@" in h:
        raise Err("userinfo in target rejected")
    if h.startswith("["):
        if "]" not in h:
            raise Err("invalid ipv6 literal")
        h = h[1:h.index("]")]
    elif h.count(":") == 1 and h.rsplit(":", 1)[1].isdigit():
        h = h.rsplit(":", 1)[0]
    return h


def vso_cfg_port(tgt, dflt):
    if tgt.startswith("["):
        tail = tgt[tgt.index("]") + 1:]
        if tail.startswith(":") and tail[1:].isdigit():
            return int(tail[1:])
        return dflt
    if tgt.count(":") == 1:
        tail = tgt.rsplit(":", 1)[1]
        if tail.isdigit():
            return int(tail)
    return dflt


def inf_is_local(addr):
    ip = ipaddress.ip_address(addr)
    return bool(ip.is_loopback or ip.is_link_local or ip.is_private
                or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def vso_res(host, port, cfg):
    t0 = time.perf_counter()
    res = {"ok": False, "err": None, "ms": 0.0, "peers": []}
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        res["err"] = f"dns:{e.errno}"
        return res
    res["peers"] = sorted({i[4][0] for i in infos})
    last = None
    for fam, typ, _pr, _cn, sa in infos:
        s = socket.socket(fam, typ)
        s.settimeout(cfg.timeout)
        for _ in range(cfg.retry):
            try:
                a = time.perf_counter()
                s.connect(sa)
                res["ms"] = round((time.perf_counter() - a) * 1000, 2)
                res["ok"] = True
                res["local"] = s.getsockname()[0]
                s.close()
                res["total_ms"] = round((time.perf_counter() - t0) * 1000, 2)
                return res
            except OSError as e:
                last = e
                time.sleep(cfg.rate)
        s.close()
    res["err"] = f"connect:{last.errno if last else 'unknown'}"
    return res


def vso_tls(host, port, cfg):
    out = {"ok": False, "err": None, "ver": None, "cipher": None, "alpn": None,
           "not_after": None, "days": None, "expired": None, "issuer": None,
           "subject": None, "san": [], "chain_ok": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=cfg.timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                out["ok"] = True
                out["ver"] = s.version()
                cip = s.cipher()
                out["cipher"] = cip[0] if cip else None
                out["alpn"] = s.selected_alpn_protocol()
                der = s.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as e:
        out["err"] = f"tls:{type(e).__name__}"
        return out
    try:
        out.update(inf_cert(der))
    except Exception as e:
        out["cert_err"] = type(e).__name__
    try:
        out["chain_ok"] = inf_chain(host, port, cfg)
    except Exception as e:
        out["chain_err"] = type(e).__name__
    return out


def inf_chain(host, port, cfg):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=cfg.timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except ssl.SSLCertVerificationError:
        return False
    except (ssl.SSLError, OSError):
        return None


def inf_cert(der):
    o = {"not_after": None, "days": None, "expired": None,
         "issuer": None, "subject": None, "san": []}
    if not der or x509 is None:
        return o
    try:
        c = x509.load_der_x509_certificate(der)
    except Exception:
        return o
    na = getattr(c, "not_valid_after_utc", None)
    if na is None:
        na = getattr(c, "not_valid_after", None)
    if na is not None:
        if na.tzinfo is None:
            na = na.replace(tzinfo=timezone.utc)
        o["not_after"] = na.isoformat()
        d = (na - datetime.now(timezone.utc)).total_seconds() / 86400
        o["days"] = int(d)
        o["expired"] = d < 0
    for attr, key in (("issuer", "issuer"), ("subject", "subject")):
        try:
            o[key] = c.issuer.rfc4514_string() if attr == "issuer" else c.subject.rfc4514_string()
        except Exception:
            o[key] = None
    try:
        ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        o["san"] = [str(g.value) for g in ext.value]
    except Exception:
        pass
    return o


def inf_weak_ver(ver):
    return bool(ver) and ver in WEAK_VER

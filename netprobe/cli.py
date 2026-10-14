import argparse
import concurrent.futures as cf
import json
import os
import socket
import sys
import time
from urllib.parse import urlsplit

from . import __version__, http, net

ACK = "I have authorization to test this target."


def vso_cfg():
    p = argparse.ArgumentParser(prog="netprobe", description="Network and TLS reachability auditor")
    p.add_argument("--version", action="version", version=f"netprobe {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("reach", help="TCP reachability, latency, rtt")
    a.add_argument("targets", nargs="+")
    a.add_argument("--port", type=int, default=443)
    a.add_argument("--timeout", type=float, default=net.TIMEOUT)
    a.add_argument("--retry", type=int, default=net.RETRY)
    a.add_argument("--rate", type=float, default=net.RATE)
    a.add_argument("--jobs", type=int, default=8)
    a.add_argument("--json", action="store_true")
    a.add_argument("--ack", default="")

    b = sub.add_parser("tls", help="certificate and protocol audit")
    b.add_argument("targets", nargs="+")
    b.add_argument("--port", type=int, default=443)
    b.add_argument("--timeout", type=float, default=net.TIMEOUT)
    b.add_argument("--retry", type=int, default=1)
    b.add_argument("--rate", type=float, default=net.RATE)
    b.add_argument("--jobs", type=int, default=4)
    b.add_argument("--json", action="store_true")
    b.add_argument("--ack", default="")

    c = sub.add_parser("web", help="HTTP security header and TLS audit")
    c.add_argument("urls", nargs="+")
    c.add_argument("--timeout", type=float, default=net.TIMEOUT)
    c.add_argument("--retry", type=int, default=1)
    c.add_argument("--rate", type=float, default=0.2)
    c.add_argument("--jobs", type=int, default=4)
    c.add_argument("--json", action="store_true")
    c.add_argument("--ack", default="")

    d = sub.add_parser("dns", help="resolver view, no zone transfer")
    d.add_argument("hosts", nargs="+")
    d.add_argument("--timeout", type=float, default=net.TIMEOUT)
    d.add_argument("--retry", type=int, default=1)
    d.add_argument("--rate", type=float, default=net.RATE)
    d.add_argument("--jobs", type=int, default=8)
    d.add_argument("--json", action="store_true")
    d.add_argument("--ack", default="")
    return p


def vso_gate(args):
    if args.ack != ACK:
        sys.stderr.write("refusing: pass --ack with the authorization statement to continue\n")
        sys.exit(2)
    hosts = getattr(args, "targets", None) or getattr(args, "urls", None) or getattr(args, "hosts", [])
    if len(hosts) > 32:
        sys.stderr.write("refusing: target count above the 32 cap for this tool\n")
        sys.exit(2)


def vso_hosts(tgts):
    out = []
    for t in tgts:
        try:
            h = net.vso_cfg_host(t)
            if h and h not in out:
                out.append(h)
        except net.Err as e:
            sys.stderr.write(f"skip {t}: {e}\n")
    return out


def vso_dns(host, cfg):
    r = {"host": host, "addrs": [], "v4": [], "v6": [], "err": None, "ms": 0.0}
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        r["err"] = f"dns:{e.errno}"
        return r
    for fam, _typ, _pr, _cn, sa in infos:
        a = sa[0]
        if a in r["addrs"]:
            continue
        r["addrs"].append(a)
        if fam == socket.AF_INET:
            r["v4"].append(a)
        elif fam == socket.AF_INET6:
            r["v6"].append(a)
    r["ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return r


def vso_run(fn, items, jobs, key, cfg):
    res = []
    with cf.ThreadPoolExecutor(max_workers=max(1, min(jobs, 16))) as ex:
        futs = {ex.submit(fn, it): it for it in items}
        for fu in cf.as_completed(futs):
            it = futs[fu]
            try:
                res.append(fu.result())
            except Exception as e:
                res.append({key: it, "err": type(e).__name__})
    return res


def vso_reach(args, cfg):
    return [dict(net.vso_res(h, args.port, cfg), host=h, port=args.port)
            for h in vso_hosts(args.targets)]


def vso_tls(args, cfg):
    hs = vso_hosts(args.targets)
    return vso_run(lambda h: dict(net.vso_tls(h, args.port, cfg), host=h, port=args.port), hs, args.jobs, "host", cfg)


def vso_web(args, cfg):
    out = []
    for u in args.urls:
        try:
            nu = http.vso_norm(u)
        except ValueError as e:
            out.append({"url": u, "res": {"ok": False, "err": f"bad-url: {e}"}, "tls": {}})
            continue
        res = http.vso_fetch(nu, cfg)
        p = urlsplit(nu)
        if p.scheme == "https":
            tls = net.vso_tls(p.hostname, p.port or 443, cfg)
        else:
            tls = {}
        out.append({"url": nu, "res": res, "tls": tls})
    return out


def vso_out(rows, as_json, render):
    if as_json:
        print(json.dumps(rows, indent=2, default=str))
        return
    if isinstance(rows, list):
        for r in rows:
            print(render(r))
            print()
    else:
        print(json.dumps(rows, indent=2, default=str))


def main(argv=None):
    args = vso_cfg().parse_args(argv)
    vso_gate(args)
    cfg = args
    if args.cmd == "reach":
        rows = vso_reach(args, cfg)
        vso_out(rows, args.json, lambda r: (f"{r.get('host')}:{r.get('port')} "
                                            f"{'ok' if r.get('ok') else 'fail'} {r.get('ms')}ms "
                                            f"err={r.get('err')} peers={r.get('peers')}"))
        return 0 if all(r.get("ok") for r in rows) else 1
    if args.cmd == "tls":
        rows = vso_tls(args, cfg)
        vso_out(rows, args.json, lambda r: (f"{r.get('host')}:{r.get('port')} {r.get('ver')} "
                                            f"{r.get('cipher')} chain={r.get('chain_ok')} "
                                            f"days={r.get('days')} san={len(r.get('san', []))} "
                                            f"err={r.get('err')}"))
        return 0
    if args.cmd == "web":
        rows = vso_web(args, cfg)
        vso_out(rows, args.json,
                lambda r: http.inf_render(r.get("res", {}), r.get("tls"), r.get("url", "")))
        worst = min((http.inf_grade(r.get("res", {}), r.get("tls"), r.get("url", ""))[2]
                     for r in rows), default=0)
        return 0 if worst >= 60 else 1
    if args.cmd == "dns":
        rows = vso_run(lambda h: vso_dns(h, cfg), vso_hosts(args.hosts), args.jobs, "host", cfg)
        vso_out(rows, args.json, lambda r: (f"{r.get('host')} {r.get('ms')}ms "
                                            f"v4={r.get('v4')} v6={r.get('v6')} err={r.get('err')}"))
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())

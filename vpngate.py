#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线 (精简版)
=====================================
流程:
  1. 获取 VPN Gate 原始节点
  2. 只保留带 TCP 入口的 SSTP 节点
  3. 去重
  4. 并发调用检测 Worker
  5. 生成 public/data.json + public/index.html + public/nodes.txt
"""

import base64
import csv
import io
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://你的域名/check?sstp=vpn:vpn@")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
_section = None

def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)

def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 数据抓取
# ---------------------------------------------------------------------------
def fetch_vpngate():
    try:
        log("VPN GATE", f"获取官方 API: {VPNGATE_API}")
        resp = requests.get(VPNGATE_API, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"})
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 返回 0 行数据")
    except Exception as exc:
        log("VPN GATE", f"官方 API 获取失败: {exc}")

    try:
        log("VPN GATE", f"回退镜像: {VPNGATE_MIRROR}")
        resp = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if rows:
            log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
            return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"回退镜像也失败: {exc}")
    die("VPN Gate 官方 API 与回退镜像均不可用, 数据源完全失败")

def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {"hostname": idx.get("hostname", 0), "ip": idx.get("ip", 1), "countrylong": idx.get("countrylong", 5), "countryshort": idx.get("countryshort", 6), "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1)}

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7: continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip: continue
        rows.append({"host": host, "ip": ip, "country_long": fields[pos["countrylong"]].strip(), "country_short": fields[pos["countryshort"]].strip(), "config_b64": fields[pos["openvpn_configdata_base64"]].strip()})
    return rows

def parse_mirror_json(data):
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip: continue
        rows.append({"host": host, "ip": ip, "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(), "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(), "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip()})
    return rows

# ---------------------------------------------------------------------------
# 筛选 SSTP 节点
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)

def to_sstp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg): continue
        m = _REMOTE_RE.search(cfg)
        if not m: continue
        port = int(m.group(1))
        if not (1 <= port <= 65535): continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({"host": host, "port": port, "ip": r["ip"], "country": r["country_long"], "country_code": r["country_short"]})
    return nodes

def dedupe(nodes):
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen: continue
        seen.add(key)
        out.append(n)
    return out

# ---------------------------------------------------------------------------
# 检测 Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    if is_datacenter is True: return "datacenter"
    if is_datacenter is False: return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS): return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS): return "residential"
    h = host.lower()
    if h.startswith("public-vpn"): return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h): return "residential"
    return "unknown"

def check_one(node, session):
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {"ip": exit_info.get("ip"), "country": exit_info.get("country"), "country_code": exit_info.get("country_code"), "city": exit_info.get("city"), "continent": exit_info.get("continent"), "asn": asn.get("asn"), "org": org, "type": asn.get("type"), "is_datacenter": exit_info.get("is_datacenter")}
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out

def check_all(nodes, session):
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results

# ---------------------------------------------------------------------------
# 生成数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {"raw_nodes": raw_count, "sstp_nodes": sstp_count, "checked": len(results), "success": len(available), "failed": len(results) - len(available), "countries": len(countries), "residential_est": sum(1 for n in available if n["residential"] == "residential"), "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter")}
    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), "source": source, "worker": WORKER_CHECK_URL, "stats": stats, "countries": by_country, "available": available}
    return data

# edgetunnel 入口地址池
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "saas.072159.xyz:443,hzytjy.cn:443,ali.nonull.pp.ua:443,auto.dolby.dpdns.org:443,"
        "cdn.cnno.de:443,saas.sin.fan:443,cf.777791.xyz:443",
    ).split(",")
    if h.strip()
]

NODES_URL = os.environ.get("NODES_URL", "https://cafbill.github.io/gate/nodes.txt")

def iter_node_lines(data):
    """按发布顺序产出 (line, entry, node)"""
    countries = data["countries"]
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    edge = [e.strip() for e in _entry.split(",") if e.strip()] or EDGE_HOSTS
    idx = 0
    ordered = sorted(countries.items(), key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])))
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(grp["nodes"], key=lambda n: (0 if n.get("residential") == "residential" else 1, n.get("latency_ms") is None, n.get("latency_ms") or 0, n.get("host") or ""))
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        dc_nodes = [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            yield (f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}", entry, n)
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            yield (f"{entry}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}", entry, n)


def build_nodes_text(data):
    """生成纯节点行版本 (无注释): 每行 = 入口地址#名字$sstp://..."""
    return "\n".join(line for line, _entry, _node in iter_node_lines(data)) + "\n"

def write_outputs(data):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = ("<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
                "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
                "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(build_nodes_text(data))

    return data_path, html_path, nodes_path

# ---------------------------------------------------------------------------
# 端到端拨测 (VLESS over WS -> Worker -> SSTP -> 204)
# ---------------------------------------------------------------------------
PROBE_ENABLE = os.environ.get("PROBE_ENABLE", "1").strip().lower() not in ("0", "false", "no", "off")
PROBE_UUID = os.environ.get("PROBE_UUID", "").strip()
PROBE_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "8"))
PROBE_CONCURRENCY = max(1, int(os.environ.get("PROBE_CONCURRENCY", "10")))
PROBE_TARGET_HOST = os.environ.get("PROBE_TARGET_HOST", "cp.cloudflare.com")
PROBE_TARGET_PORT = int(os.environ.get("PROBE_TARGET_PORT", "80"))
PROBE_TARGET_PATH = os.environ.get("PROBE_TARGET_PATH", "/generate_204")
PROBE_HOST = os.environ.get("PROBE_HOST", "").strip()


def _chain_path(exit_host, exit_port):
    """按 edgetunnel base64SecretEncode 规则生成链式代理路径"""
    payload = json.dumps(
        {"type": "sstp", "username": "vpn", "password": "vpn", "hostname": exit_host, "port": int(exit_port)},
        separators=(",", ":"),
    ).encode()
    key = PROBE_UUID.encode()
    mixed = bytes(b ^ key[i % len(key)] for i, b in enumerate(payload))
    return "/video/" + base64.b64encode(mixed).decode()


def _split_entry(entry):
    entry = (entry or "").strip()
    if entry.startswith("["):
        host, port = entry[1:].split("]:", 1)
        return host, int(port)
    if entry.count(":") == 1:
        host, port = entry.split(":", 1)
        return host, int(port)
    return entry, 443


def _ws_frame(payload):
    n = len(payload)
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    if n < 126:
        head = bytes([0x82, 0x80 | n])
    elif n < 65536:
        head = bytes([0x82, 0x80 | 126]) + struct.pack(">H", n)
    else:
        head = bytes([0x82, 0x80 | 127]) + struct.pack(">Q", n)
    return head + mask + masked


def _ws_read(ws, budget):
    """读一帧, 返回 (opcode, data)"""
    h = ws.recv(2)
    if len(h) < 2:
        return None, b""
    opcode = h[0] & 0x0F
    ln = h[1] & 0x7F
    if ln == 126:
        ln = struct.unpack(">H", ws.recv(2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", ws.recv(8))[0]
    chunk = b""
    while len(chunk) < ln:
        part = ws.recv(min(ln - len(chunk), 16384))
        if not part:
            break
        chunk += part
    return opcode, chunk


def _probe_one(entry, exit_host, exit_port, timeout=None):
    """拨测单个节点: 返回 (ok, latency_ms, error)"""
    timeout = PROBE_TIMEOUT if timeout is None else timeout
    entry_host, entry_port = _split_entry(entry)
    # Cloudflare 按 SNI 路由到 Worker: SNI/Host 必须是 Worker 域名, 而连接落在优选入口 IP 上
    sni = PROBE_HOST or entry_host
    path = _chain_path(exit_host, exit_port)
    http_req = (
        f"GET {PROBE_TARGET_PATH} HTTP/1.1\r\nHost: {PROBE_TARGET_HOST}\r\n"
        "Connection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    ).encode()
    try:
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(entry_host, entry_port, type=socket.SOCK_STREAM)})
    except Exception as exc:
        return False, 0, f"dns:{type(exc).__name__}"
    if not ips:
        return False, 0, "dns:empty"

    last_err = "unknown"
    for ip in ips[:3]:
        sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        t0 = time.time()
        try:
            sock.connect((ip, entry_port))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["http/1.1"])
            ws = ctx.wrap_socket(sock, server_hostname=sni)
            key = base64.b64encode(os.urandom(16)).decode()
            hs = (
                f"GET {path} HTTP/1.1\r\nHost: {sni}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            )
            ws.sendall(hs.encode())
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = ws.recv(4096)
                if not chunk:
                    break
                buf += chunk
            status_line = buf.split(b"\r\n")[0][:60].decode("latin1", "replace")
            if " 101" not in status_line:
                last_err = "ws:" + status_line
                continue
            t_ws = time.time() - t0
            header = (
                b"\x00" + bytes.fromhex(PROBE_UUID.replace("-", "")) + b"\x00\x01"
                + struct.pack(">H", PROBE_TARGET_PORT) + b"\x02"
                + bytes([len(PROBE_TARGET_HOST)]) + PROBE_TARGET_HOST.encode() + http_req
            )
            ws.sendall(_ws_frame(header))
            got = b""
            first = None
            while True:
                opcode, chunk = _ws_read(ws, timeout)
                if opcode is None:
                    break
                if first is None:
                    first = time.time() - t0
                got += chunk
                if len(got) > 60:
                    break
            latency = round((first if first is not None else (time.time() - t0)) * 1000)
            status_line = got.split(b"\r\n")[0] if got else b""
            if b"204" in status_line:
                return True, latency, ""
            last_err = f"bad:{status_line[:32].decode('latin1', 'replace') or 'empty'}"
            if status_line:
                return False, latency, last_err
        except Exception as exc:
            last_err = f"{type(exc).__name__}"
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return False, 0, last_err


def probe_lines(items):
    """items: [(line, entry, node)] — 原位写入 probe_ok/probe_ms/probe_error, 返回通过的 line"""
    def task(item):
        line, entry, node = item
        ok, ms, err = _probe_one(entry, node["host"], node["port"])
        return node, ok, ms, err

    with ThreadPoolExecutor(max_workers=PROBE_CONCURRENCY) as pool:
        futures = [pool.submit(task, it) for it in items]
        for fut in as_completed(futures):
            node, ok, ms, err = fut.result()
            node["probe_ok"] = ok
            node["probe_ms"] = ms or None
            if ok:
                node.pop("probe_error", None)
            else:
                node["probe_error"] = err

    return [line for line, _entry, node in items if node.get("probe_ok")]


def drop_probed_failures(data):
    """从 data 中剔除拨测失败的节点并重算统计"""
    keep = [n for n in data.get("available", []) if n.get("probe_ok")]
    dropped = len(data.get("available", [])) - len(keep)
    if not dropped:
        return 0
    data["available"] = keep
    for cname in list(data["countries"].keys()):
        grp = data["countries"][cname]
        grp["nodes"] = [n for n in grp["nodes"] if n.get("probe_ok")]
        if not grp["nodes"]:
            del data["countries"][cname]
            continue
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n.get("residential") == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n.get("residential") == "datacenter")
    st = data["stats"]
    st["success"] = len(keep)
    st["failed"] = max(0, int(st.get("checked") or 0) - len(keep))
    st["countries"] = len(data["countries"])
    st["residential_est"] = sum(1 for n in keep if n.get("residential") == "residential")
    st["datacenter_est"] = sum(1 for n in keep if n.get("residential") == "datacenter")
    st["probe_dropped"] = dropped
    return dropped

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    if uniq and not success and len(worker_errors) == len(uniq):
        die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")

    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"可用节点: {len(success)}")

    if PROBE_ENABLE and PROBE_UUID:
        items = list(iter_node_lines(data))
        log("PROBE", f"端到端拨测: {len(items)} (并发 {PROBE_CONCURRENCY}, 超时 {PROBE_TIMEOUT}s, 目标 {PROBE_TARGET_HOST}:{PROBE_TARGET_PORT})")
        t1 = time.time()
        kept = probe_lines(items)
        log("PROBE", f"拨测通过: {len(kept)}  剔除: {len(items) - len(kept)}  耗时: {time.time() - t1:.1f}s")
        if items and not kept:
            die("端到端拨测全部失败 — 入口或 Worker 链路异常, 本次运行判定失败 (不生成空结果)")
        dropped = drop_probed_failures(data)
        if dropped:
            log("PROBE", f"已从结果中剔除 {dropped} 个拨不通节点")
    else:
        log("PROBE", "跳过端到端拨测 (PROBE_UUID 未配置)")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    data_path, html_path, nodes_path = write_outputs(data)
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(nodes_path, REPO_DIR)}")
    log("USAGE", f"自动轮换: 把 {NODES_URL} 填入 edgetunnel 后台「自定义优选IP」框 (一次配置, 之后每 30 分钟自动更新)")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")

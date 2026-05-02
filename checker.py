#!/usr/bin/env python3
"""
VpnMihomoCheker
Автоматическая проверка VPN ключей из открытых подписок через Mihomo.

Этапы:
  1. Сбор ключей из subscriptions.txt
  2. Дедупликация по (host, port, uuid/password)
  3. TCP пре-фильтр
  4. Mihomo batch проверка (listeners режим)
  5. GeoIP + именование ключей
  6. Сохранение результатов
"""

import argparse
import asyncio
import base64
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings()

# ─── Пути ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
SUBS_FILE = BASE_DIR / "subscriptions.txt"
RESULTS = BASE_DIR / "results"
COUNTRIES = RESULTS / "countries"
BIN_DIR = BASE_DIR / "bin"
TMP_DIR = BASE_DIR / ".tmp"

RESULTS.mkdir(exist_ok=True)
COUNTRIES.mkdir(exist_ok=True)
BIN_DIR.mkdir(exist_ok=True)
TMP_DIR.mkdir(exist_ok=True)

# ─── Конфигурация ─────────────────────────────────────────────────────────────
CFG = {
    "test_url": "http://cp.cloudflare.com/generate_204",
    "timeout": 3,
    "tcp_timeout": 2.0,
    "tcp_workers": 300,
    "workers": 10,
    "batch_size": 50,
    "max_internal": 50,
    "warmup_ms": 600,
    "max_ping_ms": 0,
    "startup_timeout": 5.0,
    "kill_delay": 0.05,
}

# ─── Allowed SS ciphers ───────────────────────────────────────────────────────
SS_ALLOWED = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "none",
    "plain",
}


# ─── Флаги стран ──────────────────────────────────────────────────────────────
def country_flag(code: str) -> str:
    code = (code or "").upper().strip()
    if len(code) != 2:
        return "🌍"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def shorten_provider(name: str) -> str:
    if not name:
        return ""
    shortcuts = {
        "DigitalOcean": "DO",
        "Digital Ocean": "DO",
        "Amazon": "AWS",
        "Google": "GCP",
        "Microsoft": "Azure",
        "Hetzner Online": "Hetzner",
        "OVH": "OVH",
        "Vultr": "Vultr",
        "Cloudflare": "CF",
        "Contabo": "Contabo",
        "Aeza": "Aeza",
        "Selectel": "Selectel",
        "TimeWeb": "TimeWeb",
        "BlueVPS": "BlueVPS",
    }
    for k, v in shortcuts.items():
        if k.lower() in name.lower():
            return v
    name = re.sub(r"^AS\d+\s+", "", name).strip()
    return name[:28] + "..." if len(name) > 28 else name


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 0: Установка Mihomo
# ═══════════════════════════════════════════════════════════════════════════════


def get_mihomo_path() -> Path:
    name = "mihomo.exe" if platform.system() == "Windows" else "mihomo"
    return BIN_DIR / name


def is_mihomo_installed() -> bool:
    return get_mihomo_path().exists()


def install_mihomo():
    import gzip

    print("\u2b07\ufe0f  Mihomo...")
    system = platform.system().lower()
    machine = platform.machine().lower()

    # \u041e\u043f\u0440\u0435\u0434\u0435\u043b\u044f\u0435\u043c \u0431\u0430\u0437\u043e\u0432\u043e\u0435 \u0438\u043c\u044f asset \u0438 \u0440\u0430\u0441\u0448\u0438\u0440\u0435\u043d\u0438\u0435
    if system == "windows":
        asset_prefix = "mihomo-windows-amd64"
        ext = ".zip"
    elif system == "linux":
        if "aarch64" in machine or "arm64" in machine:
            asset_prefix = "mihomo-linux-arm64"
        else:
            asset_prefix = "mihomo-linux-amd64"
        ext = ".gz"
    else:  # macOS
        asset_prefix = (
            "mihomo-darwin-arm64" if "arm" in machine else "mihomo-darwin-amd64"
        )
        ext = ".gz"

    # GitHub API
    api = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
    try:
        resp = requests.get(
            api, timeout=15, headers={"User-Agent": "VpnMihomoCheker/1.0"}
        )
        resp.raise_for_status()
        data = resp.json()
        tag = data["tag_name"]
        assets = data["assets"]
    except Exception as e:
        sys.exit(f"GitHub API error: {e}")

    print(f"   Version: {tag}, looking for: {asset_prefix}*{ext} (no cgo)")

    # \u0418\u0449\u0435\u043c asset:
    # \u041f\u0440\u0438\u043e\u0440\u0438\u0442\u0435\u0442: \u0442\u043e\u0447\u043d\u043e\u0435 \u0438\u043c\u044f (\u0431\u0435\u0437 go-suffix), \u0437\u0430\u0442\u0435\u043c \u043b\u044e\u0431\u043e\u0435 \u043f\u043e\u0434\u0445\u043e\u0434\u044f\u0449\u0435\u0435
    url = None
    # \u0421\u043d\u0430\u0447\u0430\u043b\u0430 \u0438\u0449\u0435\u043c \u0442\u043e\u0447\u043d\u043e\u0435 \u0441\u043e\u0432\u043f\u0430\u0434\u0435\u043d\u0438\u0435: mihomo-linux-amd64-v1.19.24.gz (\u0431\u0435\u0437 cgo \u0438 go-suffix)
    exact_name = f"{asset_prefix}-{tag.lstrip('v')}{ext}"
    for a in assets:
        if a["name"] == exact_name:
            url = a["browser_download_url"]
            break

    # \u0415\u0441\u043b\u0438 \u043d\u0435 \u043d\u0430\u0448\u043b\u0438 \u2014 \u0431\u0435\u0440\u0451\u043c \u043b\u044e\u0431\u043e\u0439 c asset_prefix, \u0431\u0435\u0437 cgo, \u0431\u0435\u0437 go-suffix
    if not url:
        for a in assets:
            n = a["name"]
            if (
                n.startswith(asset_prefix)
                and n.endswith(ext)
                and "cgo" not in n
                and not re.search(r"-go\d+", n)
            ):
                url = a["browser_download_url"]
                break

    # \u0422\u0440етьй вариант: любой с asset_prefix
    if not url:
        for a in assets:
            n = a["name"]
            if n.startswith(asset_prefix) and n.endswith(ext) and "cgo" not in n:
                url = a["browser_download_url"]
                break

    if not url:
        names = [a["name"] for a in assets if asset_prefix in a["name"]]
        sys.exit(f"No asset found for {asset_prefix}*{ext}.\nAvailable: {names[:5]}")

    print(f"   Downloading: {url}")
    r = requests.get(
        url, timeout=300, stream=True, headers={"User-Agent": "VpnMihomoCheker/1.0"}
    )
    r.raise_for_status()

    dl_path = TMP_DIR / f"mihomo_dl{ext}"
    with open(dl_path, "wb") as f:
        for chunk in r.iter_content(65536):
            f.write(chunk)

    target = get_mihomo_path()

    if ext == ".gz":
        # Linux/macOS: .gz = gzip-\u0441\u0436\u0430\u0442\u044b\u0439 \u0431\u0438\u043d\u0430\u0440\u043d\u0438\u043a
        with gzip.open(dl_path, "rb") as gz_in, open(target, "wb") as out:
            shutil.copyfileobj(gz_in, out)
        os.chmod(
            target, os.stat(target).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
        )
    else:
        # Windows: .zip
        with zipfile.ZipFile(dl_path) as z:
            exe_entry = None
            for name in z.namelist():
                if "mihomo" in name.lower() and name.endswith(".exe"):
                    exe_entry = name
                    break
            if exe_entry:
                with z.open(exe_entry) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            else:
                z.extractall(BIN_DIR)

    if target.exists():
        print(f"Mihomo installed: {target}")
    else:
        sys.exit(f"Mihomo binary not found after extraction: {target}")


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 1: Сбор ключей из подписок
# ═══════════════════════════════════════════════════════════════════════════════


def load_subscription_urls() -> list[str]:
    urls = []
    with open(SUBS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def decode_content(text: str) -> str:
    """Автодетект base64 и декодирование."""
    text = text.strip()
    protocols = ("vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://")
    if any(text.startswith(p) for p in protocols):
        return text
    # Пробуем base64
    try:
        padded = text + "=" * (4 - len(text) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if any(p in decoded for p in protocols):
            return decoded
    except Exception:
        pass
    return text


def extract_keys(text: str) -> list[str]:
    """Извлекает VPN URI из текста."""
    keys = []
    for line in text.splitlines():
        line = line.strip()
        if any(
            line.startswith(p)
            for p in (
                "vless://",
                "vmess://",
                "trojan://",
                "ss://",
                "hy2://",
                "hysteria2://",
            )
        ):
            keys.append(line)
    return keys


def fetch_all_keys(urls: list[str]) -> list[str]:
    all_keys = []
    print(f"📥 Загружаю {len(urls)} подписок...")

    def fetch_one(url):
        try:
            r = requests.get(
                url, timeout=15, verify=False, headers={"User-Agent": "Mozilla/5.0"}
            )
            if r.status_code >= 400:
                return []
            text = decode_content(r.text)
            return extract_keys(text)
        except Exception:
            return []

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(fetch_one, u): u for u in urls}
        done = 0
        for fut in as_completed(futures):
            keys = fut.result()
            all_keys.extend(keys)
            done += 1
            print(
                f"\r   {done}/{len(urls)} подписок | {len(all_keys)} ключей",
                end="",
                flush=True,
            )

    print(f"\n✅ Собрано: {len(all_keys)} ключей")
    return all_keys


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 2: Умная дедупликация
# ═══════════════════════════════════════════════════════════════════════════════


def pad_b64(s: str) -> str:
    return s + "=" * (4 - len(s) % 4)


def get_uri_identity(uri: str):
    """Возвращает tuple для дедупликации. None если не распарсился."""
    try:
        clean = uri.split("#")[0].strip()

        if clean.startswith("vmess://"):
            b64 = clean[8:]
            data = json.loads(
                base64.b64decode(pad_b64(b64)).decode("utf-8", errors="ignore")
            )
            return (
                "vmess",
                str(data.get("add", "")).lower(),
                int(data.get("port", 0)),
                str(data.get("id", "")),
            )

        p = urllib.parse.urlparse(clean)
        proto = p.scheme.lower()
        host = (p.hostname or "").lower()
        port = p.port or 0

        if proto == "vless":
            return ("vless", host, port, p.username or "")

        if proto == "trojan":
            pw = urllib.parse.unquote(p.username or "")
            return ("trojan", host, port, pw)

        if proto == "ss":
            ui = p.username or ""
            # Пробуем base64 decode userinfo
            try:
                decoded = base64.b64decode(pad_b64(ui)).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    method, pw = decoded.split(":", 1)
                    return ("ss", host, port, method.lower(), pw)
            except Exception:
                pass
            if ":" in ui:
                method, pw = ui.split(":", 1)
                return ("ss", host, port, method.lower(), pw)
            return ("ss", host, port, ui)

        if proto in ("hysteria2", "hy2"):
            return ("hy2", host, port, p.username or "")

    except Exception:
        pass
    return None


def get_host_port(uri: str) -> tuple[str, int]:
    try:
        clean = uri.split("#")[0]
        if "vmess://" in clean:
            b64 = clean[8:]
            data = json.loads(
                base64.b64decode(pad_b64(b64)).decode("utf-8", errors="ignore")
            )
            return str(data.get("add", "")), int(data.get("port", 0))
        p = urllib.parse.urlparse(clean)
        return (p.hostname or "").lower(), p.port or 0
    except Exception:
        return "", 0


def deduplicate(keys: list[str]) -> list[str]:
    seen = set()
    result = []
    dupes = 0
    for k in keys:
        ident = get_uri_identity(k)
        if ident is None:
            continue
        if ident in seen:
            dupes += 1
            continue
        seen.add(ident)
        result.append(k)
    print(
        f"🔄 Дедупликация: {len(keys)} → {len(result)} ключей (убрано {dupes} дублей)"
    )
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 3: TCP пре-фильтр
# ═══════════════════════════════════════════════════════════════════════════════


async def _tcp_check(host: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _tcp_filter_async(
    uris: list[str], timeout: float, max_workers: int
) -> list[str]:
    sem = asyncio.Semaphore(max_workers)
    results = []
    lock = asyncio.Lock()
    done_count = [0]

    async def check(uri):
        host, port = get_host_port(uri)
        if not host or not port:
            async with lock:
                done_count[0] += 1
            return
        async with sem:
            ok = await _tcp_check(host, port, timeout)
        async with lock:
            done_count[0] += 1
            if ok:
                results.append(uri)
            print(
                f"\r   TCP: {done_count[0]}/{len(uris)} | живых: {len(results)}",
                end="",
                flush=True,
            )

    await asyncio.gather(*[check(u) for u in uris])
    return results


def tcp_filter(uris: list[str]) -> list[str]:
    print(f"🔍 TCP пре-фильтр {len(uris)} ключей (timeout={CFG['tcp_timeout']}s)...")
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    result = asyncio.run(
        _tcp_filter_async(uris, CFG["tcp_timeout"], CFG["tcp_workers"])
    )
    print(f"\n✅ TCP: {len(result)}/{len(uris)} доступно")
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 4: Парсер для Mihomo proxy struct
# ═══════════════════════════════════════════════════════════════════════════════


def _qs(query: str) -> dict:
    d = {}
    for part in query.lstrip("?").split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            d[urllib.parse.unquote(k)] = urllib.parse.unquote(v)
    return d


def _net_opts(proto_conf: dict) -> dict:
    raw = re.sub(
        r"[^a-z0-9]",
        "",
        (proto_conf.get("raw_type") or proto_conf.get("type") or "tcp").lower(),
    )
    path = proto_conf.get("path") or "/"
    host = proto_conf.get("host") or ""

    if raw in ("tcp", "", "none"):
        return {}
    if raw in ("ws", "websocket"):
        ws = {"path": path}
        if host:
            ws["headers"] = {"Host": host}
        return {"network": "ws", "ws-opts": ws}
    if raw in ("httpupgrade", "xhttp", "h2", "http"):
        ws = {"path": path, "v2ray-http-upgrade": True}
        if host:
            ws["headers"] = {"Host": host}
        return {"network": "ws", "ws-opts": ws}
    if raw in ("grpc", "gun"):
        sn = proto_conf.get("serviceName") or path.strip("/")
        g = {}
        if sn:
            g["grpc-service-name"] = sn
        return {"network": "grpc", "grpc-opts": g} if g else {"network": "grpc"}
    return {}


def parse_to_mihomo(uri: str) -> dict | None:
    """Конвертирует URI в mihomo proxy dict."""
    try:
        clean = uri.split("#")[0].strip()
        proto = clean.split("://")[0].lower()

        # ── VMess ────────────────────────────────────────────────────────
        if proto == "vmess":
            b64 = clean[8:]
            data = json.loads(
                base64.b64decode(pad_b64(b64)).decode("utf-8", errors="ignore")
            )
            host = data.get("add", "")
            port = int(data.get("port", 0))
            uuid = data.get("id", "")
            if not host or not port or not uuid:
                return None
            raw = re.sub(r"[^a-z0-9]", "", str(data.get("net", "tcp")).lower()) or "tcp"
            conf = {
                "raw_type": raw,
                "path": data.get("path", "/"),
                "host": data.get("host", ""),
                "serviceName": data.get("path", ""),
            }
            proxy = {
                "type": "vmess",
                "server": host,
                "port": port,
                "uuid": uuid,
                "alterId": int(data.get("aid", 0)),
                "cipher": data.get("scy", "auto") or "auto",
                "tls": data.get("tls", "") == "tls",
                "servername": data.get("sni", "") or data.get("host", ""),
                "skip-cert-verify": True,
            }
            proxy.update(_net_opts(conf))
            return proxy

        p = urllib.parse.urlparse(clean)
        qs = _qs(p.query)
        host = p.hostname or ""
        port = p.port or 0
        if not host or not port:
            return None

        sec = qs.get("security", "").lower()
        sni = qs.get("sni", "") or qs.get("peer", "") or host
        fp = qs.get("fp", "chrome") or "chrome"
        raw = re.sub(r"[^a-z0-9]", "", qs.get("type", "tcp").lower()) or "tcp"
        path_val = urllib.parse.unquote(qs.get("path", "/"))
        conf_for_net = {
            "raw_type": raw,
            "path": path_val,
            "host": qs.get("host", ""),
            "serviceName": qs.get("serviceName", ""),
        }

        # ── VLESS ────────────────────────────────────────────────────────
        if proto == "vless":
            uuid = p.username or ""
            if not uuid:
                return None
            proxy = {
                "type": "vless",
                "server": host,
                "port": port,
                "uuid": uuid,
                "tls": sec in ("tls", "reality"),
                "skip-cert-verify": True,
                "servername": sni,
                "client-fingerprint": fp,
            }
            flow = qs.get("flow", "")
            if flow:
                proxy["flow"] = flow
            if sec == "reality":
                pbk = qs.get("pbk", "")
                if not pbk:
                    return None
                reality = {"public-key": pbk}
                sid = qs.get("sid", "")
                if sid:
                    reality["short-id"] = sid
                proxy["reality-opts"] = reality
            proxy.update(_net_opts(conf_for_net))
            return proxy

        # ── Trojan ───────────────────────────────────────────────────────
        if proto == "trojan":
            pw = urllib.parse.unquote(p.username or "")
            if not pw:
                return None
            proxy = {
                "type": "trojan",
                "server": host,
                "port": port,
                "password": pw,
                "sni": sni,
                "skip-cert-verify": True,
                "tls": True,
            }
            proxy.update(_net_opts(conf_for_net))
            return proxy

        # ── Shadowsocks ──────────────────────────────────────────────────
        if proto == "ss":
            ui = p.username or ""
            method, password = "", ""
            try:
                decoded = base64.b64decode(pad_b64(ui)).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    method, password = decoded.split(":", 1)
            except Exception:
                pass
            if not method and ":" in ui:
                method, password = ui.split(":", 1)
            method = method.lower().strip()
            if method == "chacha20-poly1305":
                method = "chacha20-ietf-poly1305"
            if method not in SS_ALLOWED:
                return None
            return {
                "type": "ss",
                "server": host,
                "port": port,
                "cipher": method,
                "password": password,
            }

        # ── Hysteria2 ────────────────────────────────────────────────────
        if proto in ("hysteria2", "hy2"):
            pw = p.username or ""
            if not pw:
                return None
            proxy = {
                "type": "hysteria2",
                "server": host,
                "port": port,
                "password": pw,
                "sni": sni,
                "skip-cert-verify": True,
            }
            obfs = qs.get("obfs", "")
            if obfs and obfs != "none":
                proxy["obfs"] = obfs
                proxy["obfs-password"] = qs.get("obfs-password", "")
            return proxy

    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 4: Mihomo batch проверка
# ═══════════════════════════════════════════════════════════════════════════════


def wait_for_port(port: int, max_wait: float = 5.0) -> bool:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except Exception:
            time.sleep(0.05)
    return False


def check_via_socks5(port: int, test_url: str, timeout: int) -> int | None:
    proxies = {
        "http": f"socks5://127.0.0.1:{port}",
        "https": f"socks5://127.0.0.1:{port}",
    }
    try:
        t = time.time()
        r = requests.get(test_url, proxies=proxies, timeout=timeout, verify=False)
        ms = int((time.time() - t) * 1000)
        return ms if r.status_code < 400 else None
    except Exception:
        return None


def get_exit_ip(port: int, timeout: int = 5) -> str:
    for url in ("https://api.ipify.org", "https://icanhazip.com"):
        try:
            proxies = {
                "http": f"socks5://127.0.0.1:{port}",
                "https": f"socks5://127.0.0.1:{port}",
            }
            r = requests.get(url, proxies=proxies, timeout=timeout, verify=False)
            ip = r.text.strip()
            if ip and len(ip) < 50:
                return ip
        except Exception:
            pass
    return ""


def check_batch(
    items: list[tuple[str, int]], test_url: str, base_port: int
) -> list[dict]:
    """items = list of (uri, socks_port). Возвращает list результатов."""
    proxies_list, groups, listeners, valid = [], [], [], []

    for uri, port in items:
        struct = parse_to_mihomo(uri)
        if not struct:
            continue
        name = f"proxy_{port}"
        group = f"group_{port}"
        struct["name"] = name
        struct["udp"] = False
        proxies_list.append(struct)
        groups.append({"name": group, "type": "select", "proxies": [name]})
        listeners.append(
            {
                "name": f"in_{port}",
                "type": "socks",
                "port": port,
                "proxy": group,
                "udp": False,
            }
        )
        valid.append((uri, port))

    if not valid:
        return []

    config = {
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "global",
        "log-level": "silent",
        "ipv6": False,
        "proxies": proxies_list,
        "proxy-groups": groups,
        "listeners": listeners,
        "rules": [],
    }

    cfg_path = TMP_DIR / f"mh_{base_port}.json"
    with open(cfg_path, "w") as f:
        json.dump(config, f)

    proc = subprocess.Popen(
        [str(get_mihomo_path()), "-f", str(cfg_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    results = []
    try:
        if not wait_for_port(valid[0][1], CFG["startup_timeout"]):
            return []
        time.sleep(CFG["warmup_ms"] / 1000)

        max_w = min(len(valid), CFG["max_internal"])
        with ThreadPoolExecutor(max_workers=max_w) as ex:
            fut_map = {
                ex.submit(check_via_socks5, port, test_url, CFG["timeout"]): (uri, port)
                for uri, port in valid
            }
            for fut in as_completed(fut_map):
                uri, port = fut_map[fut]
                ms = fut.result()
                if ms is None:
                    continue
                if CFG["max_ping_ms"] and ms > CFG["max_ping_ms"]:
                    continue
                exit_ip = get_exit_ip(port, timeout=5)
                results.append(
                    {"uri": uri, "port": port, "latency": ms, "exit_ip": exit_ip}
                )
    finally:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
        time.sleep(CFG["kill_delay"])
        try:
            cfg_path.unlink()
        except Exception:
            pass

    return results


def mihomo_check_all(uris: list[str]) -> list[dict]:
    total = len(uris)
    print(
        f"🛡️  Mihomo проверка {total} ключей (batch={CFG['batch_size']}, workers={CFG['workers']})..."
    )

    base_port = 20000
    batch_size = CFG["batch_size"]

    # Формируем батчи: (uri, assigned_port)
    batches = []
    for batch_idx in range(0, total, batch_size):
        batch_uris = uris[batch_idx : batch_idx + batch_size]
        port_start = base_port + batch_idx
        batches.append([(u, port_start + i) for i, u in enumerate(batch_uris)])

    all_results = []
    done = 0
    lock = __import__("threading").Lock()

    def run_batch(items):
        nonlocal done
        res = check_batch(items, CFG["test_url"], items[0][1])
        with lock:
            all_results.extend(res)
            done += len(items)
            print(
                f"\r   {done}/{total} проверено | рабочих: {len(all_results)}",
                end="",
                flush=True,
            )
        return res

    with ThreadPoolExecutor(max_workers=CFG["workers"]) as ex:
        list(ex.map(run_batch, batches))

    print(f"\n✅ Рабочих ключей: {len(all_results)}/{total}")
    return all_results


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 5: GeoIP и именование
# ═══════════════════════════════════════════════════════════════════════════════

_geo_cache: dict[str, dict] = {}


def geoip(ip: str) -> dict:
    if not ip:
        return {}
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org",
            timeout=5,
        )
        data = r.json()
        if data.get("status") == "success":
            _geo_cache[ip] = data
            return data
    except Exception:
        pass
    _geo_cache[ip] = {}
    return {}


def geoip_batch(ips: list[str], max_rps: int = 40) -> dict[str, dict]:
    """Batch GeoIP с ограничением запросов в секунду (ip-api.com: 45 req/min free)."""
    unique = list({ip for ip in ips if ip and ip not in _geo_cache})
    if not unique:
        return _geo_cache

    print(f"🌍 GeoIP для {len(unique)} IP...")
    interval = 1.0 / max_rps

    with ThreadPoolExecutor(max_workers=max_rps) as ex:
        for i, ip in enumerate(unique):
            if i > 0:
                time.sleep(interval)
            ex.submit(geoip, ip)
    return _geo_cache


def build_tag(country: str, country_code: str, provider: str, num: int) -> str:
    flag = country_flag(country_code)
    prov = shorten_provider(provider)
    if prov:
        return f"{flag} {country} | {prov} {num}"
    return f"{flag} {country} {num}"


def rename_key(
    uri: str, country: str, country_code: str, provider: str, num: int
) -> str:
    base = uri.split("#")[0].rstrip()
    tag = build_tag(country, country_code, provider, num)
    return f"{base}#{tag}"


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 6: Сохранение результатов
# ═══════════════════════════════════════════════════════════════════════════════

SUB_HEADER = """\
#profile-update-interval: 3
#profile-title: encode:{title}
#subscription-userinfo: upload=0; download=0; total=107374182400; expire=1893456000
#support-url: https://github.com/
#profile-web-page-url: https://github.com/
"""


def save_results(working: list[dict]):
    # Собираем GeoIP для всех exit IP
    ips = [r["exit_ip"] for r in working if r.get("exit_ip")]
    geo_data = geoip_batch(ips)

    # Группируем по провайдеру для нумерации
    # Счётчик: (country_code, provider) → номер
    counters: dict[tuple, int] = defaultdict(int)

    # Обогащаем результаты
    enriched = []
    for r in working:
        geo = geoip(r.get("exit_ip", "")) if r.get("exit_ip") else {}
        host, _ = get_host_port(r["uri"])
        if not geo:
            geo = geoip(host)

        country = geo.get("country", "Unknown")
        country_code = geo.get("countryCode", "XX")
        org = geo.get("org", "") or geo.get("isp", "")
        provider = shorten_provider(org)

        key = (country_code, provider)
        counters[key] += 1
        num = counters[key]

        final_uri = rename_key(r["uri"], country, country_code, org, num)
        enriched.append(
            {
                **r,
                "country": country,
                "country_code": country_code,
                "provider": provider,
                "final_uri": final_uri,
            }
        )

    # Сортируем: по стране → по пингу
    enriched.sort(key=lambda x: (x["country"], x["latency"]))

    # ── all_working.txt ───────────────────────────────────────────────────────
    all_keys = [r["final_uri"] for r in enriched]
    (RESULTS / "all_working.txt").write_text("\n".join(all_keys), encoding="utf-8")

    # ── all_working_sub.txt (base64) ──────────────────────────────────────────
    header = SUB_HEADER.format(title="BobiVPN ✅ All Countries")
    content = header + "\n".join(all_keys)
    b64 = base64.b64encode(content.encode("utf-8")).decode()
    (RESULTS / "all_working_sub.txt").write_text(b64, encoding="utf-8")

    # ── countries/*.txt ───────────────────────────────────────────────────────
    by_country: dict[str, list] = defaultdict(list)
    for r in enriched:
        by_country[r["country_code"]].append(r)

    # Очищаем старые файлы
    for f in COUNTRIES.glob("*.txt"):
        f.unlink()

    for code, items in by_country.items():
        if not items:
            continue
        country_name = items[0]["country"]
        flag = country_flag(code)
        title = f"BobiVPN {flag} {country_name}"
        header = SUB_HEADER.format(title=title)
        keys = [r["final_uri"] for r in sorted(items, key=lambda x: x["latency"])]
        content = header + "\n".join(keys)
        # Сохраняем raw
        (COUNTRIES / f"{code}.txt").write_text(content, encoding="utf-8")

    # ── stats.json ────────────────────────────────────────────────────────────
    stats = {
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "total_working": len(enriched),
        "countries": {k: len(v) for k, v in sorted(by_country.items())},
    }
    (RESULTS / "stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(f"\n💾 Результаты сохранены:")
    print(f"   all_working.txt     — {len(all_keys)} ключей")
    print(f"   all_working_sub.txt — base64 подписка")
    print(f"   countries/          — {len(by_country)} стран")
    for code, items in sorted(by_country.items(), key=lambda x: -len(x[1])):
        flag = country_flag(code)
        print(f"     {flag} {code}: {len(items)}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════


def parse_args():
    ap = argparse.ArgumentParser(description="VpnMihomoCheker")
    ap.add_argument("--timeout", type=int, default=3, help="SOCKS5 timeout (s)")
    ap.add_argument(
        "--tcp-timeout", type=float, default=2.0, help="TCP pre-filter timeout (s)"
    )
    ap.add_argument(
        "--tcp-workers", type=int, default=300, help="TCP parallel connections"
    )
    ap.add_argument("--workers", type=int, default=10, help="Mihomo parallel processes")
    ap.add_argument("--batch", type=int, default=50, help="Proxies per mihomo process")
    ap.add_argument(
        "--max-internal", type=int, default=50, help="Parallel tests per process"
    )
    ap.add_argument("--warmup", type=int, default=600, help="Mihomo warmup (ms)")
    ap.add_argument("--max-ping", type=int, default=0, help="Max ping ms (0=off)")
    ap.add_argument(
        "--test-url", type=str, default="http://cp.cloudflare.com/generate_204"
    )
    ap.add_argument("--skip-tcp", action="store_true", help="Skip TCP pre-filter")
    ap.add_argument(
        "--no-install", action="store_true", help="Don't auto-install mihomo"
    )
    return ap.parse_args()


def main():
    args = parse_args()

    # Применяем args → CFG
    CFG.update(
        {
            "test_url": args.test_url,
            "timeout": args.timeout,
            "tcp_timeout": args.tcp_timeout,
            "tcp_workers": args.tcp_workers,
            "workers": args.workers,
            "batch_size": args.batch,
            "max_internal": args.max_internal,
            "warmup_ms": args.warmup,
            "max_ping_ms": args.max_ping,
        }
    )

    print("=" * 60)
    print("  VpnMihomoCheker")
    print("=" * 60)

    # Установка Mihomo
    if not args.no_install and not is_mihomo_installed():
        install_mihomo()
    elif not is_mihomo_installed():
        sys.exit(f"❌ Mihomo не найден: {get_mihomo_path()}")

    # Шаг 1: Сбор
    urls = load_subscription_urls()
    raw_keys = fetch_all_keys(urls)

    if not raw_keys:
        sys.exit("❌ Не удалось собрать ни одного ключа")

    # Шаг 2: Дедупликация
    unique_keys = deduplicate(raw_keys)

    # Шаг 3: TCP пре-фильтр
    if args.skip_tcp:
        reachable = unique_keys
    else:
        reachable = tcp_filter(unique_keys)

    if not reachable:
        sys.exit("❌ После TCP фильтра не осталось ключей")

    # Шаг 4: Mihomo проверка
    working = mihomo_check_all(reachable)

    if not working:
        print("⚠️  Рабочих ключей не найдено")
        return

    # Шаги 5-6: GeoIP + сохранение
    save_results(working)

    print("\n✅ Готово!")


if __name__ == "__main__":
    main()

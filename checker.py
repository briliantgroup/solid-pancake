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
import statistics
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

# ─── Реальный IP машины (определяется при старте) ────────────────────────────
REAL_IP: str = ""

# ─── Счётчики фейлов (для диагностики 0 результатов) ─────────────────────────
import threading as _threading

_stats_lock = _threading.Lock()
FAIL_STATS: dict[str, int] = defaultdict(int)
DEBUG_LOG: list[str] = []  # первые 20 причин отказа с URI
DEBUG_MAX = 20  # сколько деталей сохранять


VERBOSE_LIMIT = 15  # первые N фейлов печатаем сразу
_verbose_count = 0


def _fail(reason: str, uri: str = "") -> None:
    """Атомарно инкрементирует счётчик и записывает первые N деталей."""
    global _verbose_count
    with _stats_lock:
        FAIL_STATS[reason] += 1
        if len(DEBUG_LOG) < DEBUG_MAX and uri:
            short = uri[:80] + ("..." if len(uri) > 80 else "")
            DEBUG_LOG.append(f"[{reason}] {short}")
        # Мгновенный вывод первых VERBOSE_LIMIT фейлов
        if _verbose_count < VERBOSE_LIMIT:
            _verbose_count += 1
            short_uri = (uri[:70] + "...") if len(uri) > 70 else uri
            print(
                f"\n  ❌ FAIL[{_verbose_count}] {reason}\n       {short_uri}",
                flush=True,
            )


def print_fail_stats() -> None:
    """Печатает итоговую статистику фейлов."""
    print("\n" + "=" * 60)
    print("  ДИАГНОСТИКА: почему ключи отбракованы")
    print("=" * 60)
    if not FAIL_STATS:
        print("  (нет данных — все ключи прошли или не дошли до проверки)")
    else:
        total_fail = sum(FAIL_STATS.values())
        for reason, cnt in sorted(FAIL_STATS.items(), key=lambda x: -x[1]):
            bar = "#" * min(40, int(cnt / total_fail * 40))
            print(f"  {reason:<35} {cnt:>6}  {bar}")
    if DEBUG_LOG:
        print("\n  Первые примеры:")
        for line in DEBUG_LOG:
            print(f"    {line}")
    print("=" * 60)


def detect_real_ip() -> str:
    """Узнаём реальный IP машины без прокси."""
    for url in (
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com",
    ):
        try:
            r = requests.get(url, timeout=8, verify=False)
            ip = r.text.strip()
            if ip and len(ip) < 50:
                return ip
        except Exception:
            pass
    return ""


# ─── Конфигурация ─────────────────────────────────────────────────────────────
CFG = {
    "test_url": "http://cp.cloudflare.com/generate_204",
    "timeout": 3,
    "tcp_timeout": 2.0,
    "tcp_workers": 300,
    "workers": 50,
    "batch_size": 50,
    "max_internal": 50,
    "warmup_ms": 500,
    "max_ping_ms": 0,
    "startup_timeout": 3.0,
    "kill_delay": 0.02,
    # Speed test
    "check_speed": False,  # включить замер скорости
    "min_speed_mbps": 0.0,  # минимальный порог (0 = без фильтра)
    "speed_max_mb": 10.0,  # макс. объём скачивания на тест
    "speed_timeout": 15.0,  # таймаут чтения при speed test
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
    invalid = 0  # FIX #15: считаем невалидные URI
    for k in keys:
        ident = get_uri_identity(k)
        if ident is None:
            invalid += 1
            continue
        if ident in seen:
            dupes += 1
            continue
        seen.add(ident)
        result.append(k)
    msg = f"🔄 Дедупликация: {len(keys)} → {len(result)} (дублей: {dupes}"
    if invalid:
        msg += f", невалидных: {invalid}"
    print(msg + ")")
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
    """
    Маппинг типов сети в Mihomo формат.

    БАГ был: h2 добавлялся в WS-группу — в Mihomo h2 это отдельный network тип.
    """
    raw = re.sub(
        r"[^a-z0-9]",
        "",
        (proto_conf.get("raw_type") or proto_conf.get("type") or "tcp").lower(),
    )
    path = proto_conf.get("path") or "/"
    host = proto_conf.get("host") or ""

    if raw in ("tcp", "", "none"):
        return {}

    # WebSocket
    if raw in ("ws", "websocket"):
        ws = {"path": path}
        if host:
            ws["headers"] = {"Host": host}
        return {"network": "ws", "ws-opts": ws}

    # HTTP Upgrade (отдельный тип в Mihomo 1.17+)
    if raw == "httpupgrade":
        opts: dict = {"path": path}
        if host:
            opts["host"] = host
        return {"network": "http-upgrade", "http-upgrade-opts": opts}

    # xhttp — Mihomo не поддерживает, падаем на WS как fallback
    if raw == "xhttp":
        ws = {"path": path, "v2ray-http-upgrade": True}
        if host:
            ws["headers"] = {"Host": host}
        return {"network": "ws", "ws-opts": ws}

    # HTTP/2 — отдельный network в Mihomo, НЕ WS!
    if raw in ("h2", "http"):
        h2: dict = {}
        if host:
            h2["host"] = [host]
        if path and path != "/":
            h2["path"] = path
        return {"network": "h2", "h2-opts": h2} if h2 else {"network": "h2"}

    # gRPC
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
                # FIX #11: VMess gRPC serviceName — сначала проверяем специальное поле,
                # если нет — берём из path (как в оригинальном VMess формате)
                "serviceName": data.get("serviceName") or data.get("path", ""),
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

    except Exception as e:
        proto = uri.split("://")[0].lower() if "://" in uri else "unknown"
        _fail(f"parse_exception({proto},{type(e).__name__})", uri)
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
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }
    try:
        t = time.time()
        r = requests.get(test_url, proxies=proxies, timeout=timeout, verify=False)
        ms = int((time.time() - t) * 1000)
        return ms if r.status_code < 400 else None
    except Exception:
        return None


def get_exit_info(port: int, timeout: int = 5) -> tuple[str, int, bool]:
    """
    Возвращает (exit_ip, fraud_score, is_datacenter).
    fraud_score: 0-100 (высокий = подозрительный/засвеченный IP).
    is_datacenter: True если хостинг/датацентр.
    Использует ip-api.com с полями proxy,hosting.
    """
    proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }
    # Сначала получаем IP
    exit_ip = ""
    for url in ("https://api.ipify.org", "https://icanhazip.com"):
        try:
            r = requests.get(url, proxies=proxies, timeout=timeout, verify=False)
            ip = r.text.strip()
            if ip and len(ip) < 50:
                exit_ip = ip
                break
        except Exception:
            pass

    fraud_score = 0
    is_datacenter = False

    if exit_ip:
        try:
            r = requests.get(
                f"http://ip-api.com/json/{exit_ip}?fields=status,proxy,hosting,as",
                timeout=5,
            )
            data = r.json()
            if data.get("status") == "success":
                # proxy=true → IP засвечен как прокси в базах → +50 к fraud score
                if data.get("proxy"):
                    fraud_score += 50
                # hosting=true → датацентр (не всегда плохо, но учитываем)
                is_datacenter = bool(data.get("hosting"))
        except Exception:
            pass

    return exit_ip, fraud_score, is_datacenter


def check_dns_leak(port: int, timeout: int = 5) -> bool:
    """
    Проверяет нет ли DNS leak: DNS запросы должны идти через VPN.
    Использует edns.ip-api.com — возвращает IP DNS резолвера.
    Если DNS резолвер == REAL_IP → утечка.
    Возвращает True если всё OK (нет утечки).
    """
    proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }
    try:
        r = requests.get(
            "http://edns.ip-api.com/json",
            proxies=proxies,
            timeout=timeout,
            verify=False,
        )
        data = r.json()
        dns_ip = data.get("dns", {}).get("ip", "")
        # Если DNS resolver IP совпадает с реальным IP машины — утечка
        if dns_ip and REAL_IP and dns_ip == REAL_IP:
            return False  # DNS leak!
        return True  # OK
    except Exception:
        return True  # Если не можем проверить — не блокируем ключ


def ttfb_check(port: int, url: str, timeout: int) -> int | None:
    """
    TTFB (Time To First Byte) — более точная метрика latency.

    БАГ был: iter_content(1) на HTTP 204/304 (без тела) никогда не даёт байтов
    → всегда None → uptime_low для всех ключей с generate_204.

    ФИКС: для 204/304 измеряем время до заголовков ответа (это и есть настоящий TTFB).
    """
    proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }
    try:
        t = time.time()
        with requests.get(
            url, proxies=proxies, timeout=timeout, stream=True, verify=False
        ) as r:
            if r.status_code >= 400:
                return None

            # HTTP 204/304 — нет тела, но соединение успешное.
            # Время до заголовков — и есть TTFB.
            if r.status_code in (204, 304):
                return max(1, int((time.time() - t) * 1000))

            # Для других кодов — ждём первый байт тела
            for chunk in r.iter_content(1):
                if chunk:
                    return int((time.time() - t) * 1000)
            # Если тело пустое но статус ок — всё равно успех
            return max(1, int((time.time() - t) * 1000))
    except Exception:
        return None


def calculate_score(
    latency_ms: int,
    jitter_ms: float,
    uptime_ratio: float,
    https_ok: bool,
    dns_ok: bool,
    fraud_score: int,
    speed_mbps: float = 0.0,
) -> int:
    """
    Считает итоговый score ключа (0-100).

    Компоненты:
      latency  (0-25): < 100ms → 25, < 300ms → 15, < 600ms → 5
      jitter   (0-20): < 10ms  → 20, < 50ms  → 12, < 100ms → 5
      uptime   (0-20): 100%    → 20, ≥67%    → 10
      https    (0-15): работает → 15
      dns_ok   (0-10): нет leak → 10
      speed    (0-10): > 20Mbps → 10, > 5Mbps → 6, > 1Mbps → 3  (только если измерена)
    Штрафы:
      fraud_score > 0 → -10
    """
    score = 0

    # Latency
    if latency_ms < 100:
        score += 25
    elif latency_ms < 300:
        score += 15
    elif latency_ms < 600:
        score += 5

    # Jitter (FIX #16: 0.0 при 1 измерении — нейтральный балл, не 25 очков)
    if jitter_ms == 0.0:  # единственное измерение — даём средний балл
        score += 10
    elif jitter_ms < 10:
        score += 20
    elif jitter_ms < 50:
        score += 12
    elif jitter_ms < 100:
        score += 5

    # Uptime
    if uptime_ratio >= 1.0:
        score += 20
    elif uptime_ratio >= 0.67:
        score += 10

    # HTTPS
    if https_ok:
        score += 15

    # DNS no-leak
    if dns_ok:
        score += 10

    # Speed (только если измерена)
    if speed_mbps > 20:
        score += 10
    elif speed_mbps > 5:
        score += 6
    elif speed_mbps > 1:
        score += 3

    # Штраф за засвеченный IP
    if fraud_score > 0:
        score -= 10

    return max(0, min(100, score))


def get_tier(score: int) -> str:
    """S/A/B/C tier по score."""
    if score >= 80:
        return "S"
    if score >= 60:
        return "A"
    if score >= 40:
        return "B"
    return "C"


# ── Точный speed test ────────────────────────────────────────────────────────
_SPEED_URLS = [
    "https://speed.cloudflare.com/__down?bytes=10485760",  # 10MB Cloudflare
    "https://proof.ovh.net/files/10Mb.dat",  # 10MB OVH
    "http://speedtest.tele2.net/10MB.zip",  # 10MB Tele2
    "https://speed.hetzner.de/10MB.bin",  # 10MB Hetzner
]


def measure_speed(port: int) -> float:
    """
    Точный замер скорости через SOCKS5 прокси (Мбит/с).

    Ключевое: таймер стартует ПОСЛЕ получения заголовков (соединение установлено),
    так что latency не входит в измерение — чистая пропускная способность.
    """
    limit_bytes = int(CFG["speed_max_mb"] * 1024 * 1024)
    read_timeout = CFG["speed_timeout"]
    proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
        "Connection": "keep-alive",
    }

    for url in _SPEED_URLS:
        try:
            # timeout=(подключение, чтение) — разделяем время установки и передачи
            with requests.get(
                url,
                proxies=proxies,
                headers=headers,
                stream=True,
                timeout=(5, read_timeout),
                verify=False,
            ) as r:
                if r.status_code >= 400:
                    continue

                # ❤ Таймер стартует ЗДЕСЬ — после установки соединения,
                # поэтому latency НЕ входит в измерение
                t_start = time.time()
                total_bytes = 0

                for chunk in r.iter_content(chunk_size=65536):
                    if chunk:
                        total_bytes += len(chunk)
                    if total_bytes >= limit_bytes:
                        break
                    if (time.time() - t_start) >= read_timeout:
                        break

                elapsed = time.time() - t_start

                # Требуем минимум 200KB за 0.5с для достоверного замера
                if elapsed < 0.5 or total_bytes < 200_000:
                    continue

                mbps = (total_bytes * 8) / elapsed / 1_000_000
                return round(mbps, 2)

        except Exception:
            continue

    return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# ОДНА ПРОКСИ = ОДИН ПРОЦЕСС MIHOMO (порт create_mihomo_config_file + Checker_mihomo из MK)
# Строго 1:батч с listeners не работает — mihomo игнорирует proxy фильд в listeners.
# ═══════════════════════════════════════════════════════════════════════════════


def make_mihomo_config(proxy_struct: dict, proxy_name: str, socks_port: int) -> dict:
    """
    Конфиг 1:батч как в MK_XRAYchecker create_mihomo_config_file:
      - socks-port  (не listeners!)
      - mode: rule
      - rules: ["MATCH,MK_CHECK"]
    """
    return {
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "silent",
        "ipv6": True,
        "socks-port": socks_port,
        "proxies": [proxy_struct],
        "proxy-groups": [
            {"name": "MK_CHECK", "type": "select", "proxies": [proxy_name]}
        ],
        "rules": ["MATCH,MK_CHECK"],
    }


def check_one(uri: str, socks_port: int, test_url: str) -> dict | None:
    """
    Проверяет одну прокси через отдельный mihomo процесс.
    Порт каквалогика MK Checker_mihomo — один процесс = одна прокси.
    """
    proxy_name = f"out_{socks_port}"
    struct = parse_to_mihomo(uri)
    if not struct:
        _fail("parse_fail", uri)
        return None

    struct["name"] = proxy_name
    struct["udp"] = False

    config = make_mihomo_config(struct, proxy_name, socks_port)
    cfg_path = TMP_DIR / f"mh_{socks_port}.json"

    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    except Exception:
        return None

    # FIX #10+#14: stderr=PIPE чтобы видеть ошибки при падении,
    # дренируем в фоновом потоке чтобы не забивался pipe buffer
    proc = subprocess.Popen(
        [str(get_mihomo_path()), "-f", str(cfg_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    _stderr_buf: list[bytes] = []

    def _drain_stderr():
        try:
            data = proc.stderr.read() if proc.stderr else b""
            if data:
                _stderr_buf.append(data)
        except Exception:
            pass

    _drain_t = __import__("threading").Thread(target=_drain_stderr, daemon=True)
    _drain_t.start()

    result = None
    try:
        # Поллинг порта (как wait_for_core_start в MK)
        max_wait = max(CFG["startup_timeout"], 4.0)
        if not wait_for_port(socks_port, max_wait):
            if proc.poll() is not None:
                # Читаем из буфера дренера stderr
                _drain_t.join(timeout=1.0)
                err_bytes = b"".join(_stderr_buf)
                err_msg = (
                    err_bytes.decode(errors="ignore").strip()[-200:] or "no stderr"
                )
                _fail(f"proc_died: {err_msg[:80]}", uri)
            else:
                _fail("port_timeout", uri)
            return None

        # Прогрев после открытия порта
        time.sleep(CFG["warmup_ms"] / 1000)

        if proc.poll() is not None:
            _fail("proc_died_after_warmup", uri)
            return None

        t = CFG["timeout"]

        # ── 1. TTFB + Uptime ─────────────────────────────────────────────────
        # ФИКС #5: если первая попытка удалась — не спим лишние 2с
        pings: list[int] = []
        ttfb_errors: list[str] = []
        for attempt in range(3):
            ms_i = ttfb_check(socks_port, test_url, t)
            if ms_i is None:
                ttfb_errors.append(f"attempt{attempt + 1}=None")
                time.sleep(0.35)
                ms_i = ttfb_check(socks_port, test_url, t)
                if ms_i is None:
                    ttfb_errors.append(f"retry{attempt + 1}=None")
            if ms_i is not None:
                pings.append(ms_i)
                if len(pings) >= 1:
                    break  # достаточно одного успеха для основного результата
            else:
                if attempt < 2:
                    time.sleep(
                        0.5
                    )  # короткая пауза перед следующей попыткой (вместо sleep 1.0)

        # FIX #8: если прервали после 1го успеха — считаем 100% uptime
        # При полном проходе (3 попытки) сохраняем относительный uptime
        attempts_made = attempt + 1  # noqa: F821  (defined in loop above)
        uptime_ratio = len(pings) / attempts_made if pings else 0.0

        if not pings:  # ни одного успеха из всех попыток
            errs = ",".join(ttfb_errors[:3]) or "all_none"
            _fail(f"uptime_low({errs})", uri)
            return None

        ms = round(sum(pings) / len(pings))  # средний latency
        jitter = (max(pings) - min(pings)) if len(pings) > 1 else 0.0

        if CFG["max_ping_ms"] and ms > CFG["max_ping_ms"]:
            _fail(f"max_ping_exceeded({ms}>{CFG['max_ping_ms']})", uri)
            return None
        if ms < 5:  # подозрительно быстро
            _fail(f"ping_too_low({ms}ms)", uri)
            return None

        # ── 2. HTTPS тест ──────────────────────────────────────────────────────
        # ФИКС #4: HTTPS не блокирует ключ — многие прокси блокируют Google/Cloudflare,
        # но всё равно работают через HTTP. HTTPS теперь влияет только на score.
        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        https_ok = False
        for https_url in (
            "https://cp.cloudflare.com/generate_204",
            "https://www.google.com/generate_204",
        ):
            try:
                r = requests.get(https_url, proxies=proxies, timeout=t, verify=False)
                if r.status_code < 400:
                    https_ok = True
                    break
            except Exception:
                pass
        # Не return None! Прописываем фейл для статистики, но не блокируем
        if not https_ok:
            _fail(f"https_fail_soft(score-only)", uri)

        # ── 3. Exit IP + Fraud Score + Datacenter flag ──────────────────────────
        exit_ip, fraud_score, is_datacenter = get_exit_info(socks_port, timeout=4)

        if exit_ip and REAL_IP and exit_ip == REAL_IP:
            _fail("ip_leak", uri)
            return None  # IP leak — трафик не идёт через VPN

        # ── 4. DNS Leak test ─────────────────────────────────────────────────────────
        dns_ok = check_dns_leak(socks_port, timeout=4)

        # ── 5. Speed test (если включён) ───────────────────────────────────────
        speed_mbps = measure_speed(socks_port) if CFG["check_speed"] else 0.0
        if CFG["check_speed"] and CFG["min_speed_mbps"] > 0:
            if speed_mbps < CFG["min_speed_mbps"]:
                _fail(f"speed_too_low({speed_mbps:.1f}<{CFG['min_speed_mbps']})", uri)
                return None

        # ── 6. Score + Tier ─────────────────────────────────────────────────
        score = calculate_score(
            latency_ms=ms,
            jitter_ms=jitter,
            uptime_ratio=uptime_ratio,
            https_ok=https_ok,
            dns_ok=dns_ok,
            fraud_score=fraud_score,
            speed_mbps=speed_mbps,
        )
        tier = get_tier(score)

        result = {
            "uri": uri,
            "latency": ms,
            "jitter": round(jitter, 1),
            "uptime_ratio": round(uptime_ratio, 2),
            "exit_ip": exit_ip,
            "fraud_score": fraud_score,
            "is_datacenter": is_datacenter,
            "dns_ok": dns_ok,
            "https_ok": https_ok,
            "speed_mbps": speed_mbps,
            "score": score,
            "tier": tier,
        }

    except Exception as e:
        _fail(f"exception({type(e).__name__})", uri)
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

    return result


def mihomo_check_all(uris: list[str]) -> list[dict]:
    """
    Параллельная проверка: N потоков (воркеров), каждый запускает СВОЙ mihomo.
    """
    import threading

    total = len(uris)
    base_port = 20000
    all_results: list[dict] = []
    lock = threading.Lock()
    done_count = [0]

    print(f"🛡️  Mihomo проверка {total} ключей (workers={CFG['workers']})...")

    workers = CFG["workers"]
    chunk_size = max(1, (total + workers - 1) // workers)

    # ╔═ Аудит портов ════════════════════════════════════════════════════════
    # Каждый воркер t_idx использует порты:
    #   base_port + t_idx*chunk_size, ..., base_port + t_idx*chunk_size + len(chunk)-1
    # Диапазоны НЕ пересекаются — каждый воркер идёт секвенциально.
    # Проверка:
    all_ranges = [
        set(
            range(
                base_port + i * chunk_size,
                base_port + i * chunk_size + min(chunk_size, total - i * chunk_size),
            )
        )
        for i in range(min(workers, total))
    ]
    for a in range(len(all_ranges)):
        for b in range(a + 1, len(all_ranges)):
            overlap = all_ranges[a] & all_ranges[b]
            if overlap:
                print(f"[BUG] Port conflict between workers {a} and {b}: {overlap}")
    # ╚══════════════════════════════════════════════════════════════

    def worker_thread(chunk: list[str], port_offset: int):
        """MK подход: последовательная проверка внутри потока, потоки параллельны между собой."""
        for i, uri in enumerate(chunk):
            port = base_port + port_offset + i
            res = check_one(uri, port, CFG["test_url"])
            with lock:
                done_count[0] += 1
                if res:
                    all_results.append(res)
                d = done_count[0]
                print(
                    f"\r   {d}/{total} проверено | рабочих: {len(all_results)}",
                    end="",
                    flush=True,
                )
                # Периодическая статистика каждые 100 ключей
                if d % 100 == 0 and FAIL_STATS:
                    top = sorted(FAIL_STATS.items(), key=lambda x: -x[1])[:4]
                    top_str = " | ".join(f"{r}:{c}" for r, c in top)
                    print(f"\n  [стат @{d}] {top_str}", flush=True)

    threads = []
    for t_idx in range(workers):
        start = t_idx * chunk_size
        chunk = uris[start : start + chunk_size]
        if not chunk:
            break
        t = threading.Thread(target=worker_thread, args=(chunk, start), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"\n✅ Рабочих ключей: {len(all_results)}/{total}")
    print_fail_stats()
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


def geoip_batch(ips: list[str]) -> dict[str, dict]:
    """
    Batch GeoIP через ip-api.com /batch endpoint (100 IP за запрос).

    БАГ был: max_rps=40 давал 40 запр/с вместо 45/мин → ip-api.com блокировал всё.
    ФИКС: POST /batch принимает 100 IP за один запрос — намного эффективнее.
    """
    unique = [ip for ip in {ip for ip in ips if ip} if ip not in _geo_cache]
    if not unique:
        return _geo_cache

    print(f"🌍 GeoIP для {len(unique)} IP (через batch)...")
    fields = "status,country,countryCode,city,isp,org"
    batch_size = 100

    for i in range(0, len(unique), batch_size):
        chunk = unique[i : i + batch_size]
        try:
            payload = [{"query": ip, "fields": fields} for ip in chunk]
            r = requests.post(
                "http://ip-api.com/batch",
                json=payload,
                timeout=10,
            )
            data = r.json()
            if isinstance(data, list):
                for j, item in enumerate(data):
                    ip = chunk[j]
                    if item.get("status") == "success":
                        _geo_cache[ip] = item
                    else:
                        _geo_cache[ip] = {}
        except Exception:
            # fallback: записываем пустые чтобы не перезапрашивать
            for ip in chunk:
                if ip not in _geo_cache:
                    _geo_cache[ip] = {}
        # Между батчами: 1.5с — ip-api.com допускает 15 batch-запросов/мин
        if i + batch_size < len(unique):
            time.sleep(1.5)

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


def _sub_header(title: str) -> str:
    """
    Генерирует заголовок подписки.
    FIX #13: encode: в Clash/Mihomo требует base64, а не plain text.
    """
    encoded_title = base64.b64encode(title.encode("utf-8")).decode()
    return (
        "#profile-update-interval: 3\n"
        f"#profile-title: encode:{encoded_title}\n"
        "#subscription-userinfo: upload=0; download=0; total=107374182400; expire=1893456000\n"
        "#support-url: https://github.com/\n"
        "#profile-web-page-url: https://github.com/\n"
    )


# Оставляем для обратной совместимости (speed_pass может использовать)
def SUB_HEADER_COMPAT(title: str) -> str:
    return _sub_header(title)


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

    # Приоритет стран: RU → FI → DE → NL → дальше по алфавиту
    COUNTRY_PRIORITY = {
        "RU": 1,
        "FI": 2,
        "DE": 3,
        "NL": 4,
        "FR": 5,
        "GB": 6,
        "SE": 7,
        "NO": 8,
        "CH": 9,
        "AT": 10,
        "PL": 11,
        "CZ": 12,
        "US": 13,
        "CA": 14,
        "JP": 15,
        "SG": 16,
        "HK": 17,
        "TR": 18,
        "UA": 19,
        "BY": 20,
    }

    def sort_key(r):
        code = r.get("country_code", "XX")
        prio = COUNTRY_PRIORITY.get(code, 999)
        return (prio, code, r["latency"])

    enriched.sort(key=sort_key)

    # Фильтруем C-tier если слишком много ключей (оставляем S/A/B)
    # C-tier можно убрать чтобы не засорять подписки
    # enriched = [r for r in enriched if r.get("tier", "C") != "C"]

    # Группировка по tier
    by_tier = {"S": [], "A": [], "B": [], "C": []}
    for r in enriched:
        by_tier[r.get("tier", "C")].append(r)

    # ── all_working.txt ───────────────────────────────────────────────────────
    all_keys = [r["final_uri"] for r in enriched]
    (RESULTS / "all_working.txt").write_text("\n".join(all_keys), encoding="utf-8")

    # ── all_working_sub.txt (base64) ──────────────────────────────────────────
    header = _sub_header("BobiVPN ✅ All Countries")
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
        header = _sub_header(title)
        keys = [r["final_uri"] for r in sorted(items, key=lambda x: x["latency"])]
        content = header + "\n".join(keys)
        # Сохраняем raw
        (COUNTRIES / f"{code}.txt").write_text(content, encoding="utf-8")

    # ── top_200.txt — 200 лучших по скорости (или score если speed off) ──────
    has_speed = any(r.get("speed_mbps", 0) > 0 for r in enriched)
    # top_200: берём S + A tier, сортируем по score
    top_pool = by_tier["S"] + by_tier["A"]
    if not top_pool:
        top_pool = enriched
    if has_speed:
        top = sorted(top_pool, key=lambda x: -x.get("speed_mbps", 0))[:200]
    else:
        top = sorted(top_pool, key=lambda x: -x.get("score", 0))[:200]

    top_header = _sub_header("BobiVPN 🚀 Top 200 Fastest")
    top_content = top_header + "\n".join(r["final_uri"] for r in top)
    (RESULTS / "top_200.txt").write_text(top_content, encoding="utf-8")

    top_b64 = base64.b64encode(top_content.encode("utf-8")).decode()
    (RESULTS / "top_200_sub.txt").write_text(top_b64, encoding="utf-8")

    # ── stats.json ──────────────────────────────────────────────────────────────────
    latencies = [r["latency"] for r in enriched]
    jitters = [r.get("jitter", 0) for r in enriched]
    speeds = [r["speed_mbps"] for r in enriched if r.get("speed_mbps", 0) > 0]
    scores = [r.get("score", 0) for r in enriched]

    stats = {
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "total_working": len(enriched),
        "tier_s": len(by_tier["S"]),
        "tier_a": len(by_tier["A"]),
        "tier_b": len(by_tier["B"]),
        "tier_c": len(by_tier["C"]),
        "avg_score": round(sum(scores) / len(scores), 1) if scores else 0,
        "avg_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0,
        "min_latency_ms": min(latencies) if latencies else 0,
        "p95_latency_ms": sorted(latencies)[int(len(latencies) * 0.95)]
        if latencies
        else 0,
        "avg_jitter_ms": round(sum(jitters) / len(jitters), 1) if jitters else 0,
        "avg_speed_mbps": round(sum(speeds) / len(speeds), 2) if speeds else 0,
        "max_speed_mbps": max(speeds) if speeds else 0,
        "speed_checked": has_speed,
        "countries": {
            k: {
                "count": len(v),
                "avg_ping_ms": round(sum(r["latency"] for r in v) / len(v), 1),
                "avg_score": round(sum(r.get("score", 0) for r in v) / len(v), 1),
                "tier_s": sum(1 for r in v if r.get("tier") == "S"),
                "tier_a": sum(1 for r in v if r.get("tier") == "A"),
            }
            for k, v in sorted(by_country.items())
        },
    }
    (RESULTS / "stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # S-tier отдельный файл
    s_keys = [r["final_uri"] for r in by_tier["S"]]
    if s_keys:
        s_header = _sub_header("BobiVPN ⭐ S-Tier Elite")
        (RESULTS / "tier_s.txt").write_text(
            s_header + "\n".join(s_keys), encoding="utf-8"
        )
        s_b64 = base64.b64encode((s_header + "\n".join(s_keys)).encode()).decode()
        (RESULTS / "tier_s_sub.txt").write_text(s_b64, encoding="utf-8")

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
        "--speed", action="store_true", help="Enable speed test in main pass"
    )
    ap.add_argument(
        "--speed-only",
        action="store_true",
        help="Only run speed test on already-checked keys from all_working.txt",
    )
    ap.add_argument(
        "--min-speed", type=float, default=0.0, help="Min speed Mbps (0=off)"
    )
    ap.add_argument(
        "--speed-max-mb",
        type=float,
        default=10.0,
        help="Max MB to download for speed test",
    )
    ap.add_argument(
        "--no-install", action="store_true", help="Don't auto-install mihomo"
    )
    return ap.parse_args()


def speed_pass(working: list[dict]) -> list[dict]:
    """
    Второй проход: замер скорости только на рабочих ключах без повторной пинг-проверки.
    Вход: list[{uri, latency, exit_ip, ...}]
    Выход: тот же список с заполненным speed_mbps.
    """
    import threading

    total = len(working)
    base_port = (
        25000  # Отдельный диапазон портов чтобы не пересекаться с основным проходом
    )
    workers = CFG["workers"]
    chunk_size = max(1, (total + workers - 1) // workers)
    results = [dict(r) for r in working]  # копия
    lock = threading.Lock()
    done_count = [0]

    print(f"\n⚡ Speed pass на {total} ключах (workers={workers})...")

    def worker_thread(chunk_indices: list[int], port_offset: int):
        for i, idx in enumerate(chunk_indices):
            port = base_port + port_offset + i
            uri = results[idx]["uri"]

            # Запускаем mihomo только для замера скорости
            proxy_name = f"spd_{port}"
            struct = parse_to_mihomo(uri)
            if not struct:
                with lock:
                    done_count[0] += 1
                    print(
                        f"\r   {done_count[0]}/{total} speed tested", end="", flush=True
                    )
                continue

            struct["name"] = proxy_name
            struct["udp"] = False
            config = make_mihomo_config(struct, proxy_name, port)
            cfg_path = TMP_DIR / f"spd_{port}.json"

            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(config, f)

            proc = subprocess.Popen(
                [str(get_mihomo_path()), "-f", str(cfg_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            speed = 0.0
            try:
                if wait_for_port(port, max(CFG["startup_timeout"], 3.0)):
                    time.sleep(CFG["warmup_ms"] / 1000)
                    if proc.poll() is None:
                        speed = measure_speed(port)
            except Exception:
                pass
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

            results[idx]["speed_mbps"] = speed

            with lock:
                done_count[0] += 1
                # FIX #12: avg только по уже измеренным (не всем results сразу)
                measured_speeds = [
                    r["speed_mbps"]
                    for r in results[: done_count[0]]
                    if r.get("speed_mbps", 0) > 0
                ]
                avg_now = (
                    sum(measured_speeds) / len(measured_speeds)
                    if measured_speeds
                    else 0.0
                )
                print(
                    f"\r   {done_count[0]}/{total} speed tested | avg: {avg_now:.1f} Mbps",
                    end="",
                    flush=True,
                )

    threads = []
    for t_idx in range(workers):
        start = t_idx * chunk_size
        chunk = list(range(start, min(start + chunk_size, total)))
        if not chunk:
            break
        t = threading.Thread(target=worker_thread, args=(chunk, start), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    measured = sum(1 for r in results if r.get("speed_mbps", 0) > 0)
    avg = sum(r.get("speed_mbps", 0) for r in results) / max(1, measured)
    print(f"\n✅ Speed: {measured}/{total} измерено | avg {avg:.1f} Mbps")
    return results


def load_working_from_file() -> list[dict]:
    """Load already-checked keys from results/all_working.txt."""
    path = RESULTS / "all_working.txt"
    if not path.exists():
        sys.exit(
            f"❌ {path} не найден. Сначала запусти базовую проверку без --speed-only"
        )
    keys = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    print(f"📂 Загружено {len(keys)} ключей из {path}")
    return [{"uri": k, "latency": 0, "exit_ip": "", "speed_mbps": 0.0} for k in keys]


def self_test():
    """Быстрая диагностика перед запуском."""
    ok = True

    # 1. PySocks / SOCKS5
    try:
        import socks  # noqa

        print("  [OK] PySocks installed")
    except ImportError:
        print("  [FAIL] PySocks NOT installed — pip install PySocks")
        ok = False

    # 2. requests SOCKS5 support
    # Правильный тест: socks5:// передаём через proxies=, а НЕ как URL
    try:
        import requests as _req

        _req.get(
            "http://1.1.1.1/",
            proxies={"http": "socks5://127.0.0.1:1", "https": "socks5://127.0.0.1:1"},
            timeout=0.5,
        )
    except _req.exceptions.InvalidSchema:
        # socks5:// не распознан — PySocks не работает
        print(
            "  [FAIL] requests cannot handle socks5:// proxies \u2014 pip install PySocks"
        )
        ok = False
    except Exception:
        # ConnectionError, ProxyError и т.д. — значит SOCKS5 разобрался
        print("  [OK] requests SOCKS5 support works")

    # 3. Mihomo binary
    mp = get_mihomo_path()
    if mp.exists():
        print(f"  [OK] Mihomo found: {mp}")
        try:
            r = subprocess.run([str(mp), "-v"], capture_output=True, timeout=3)
            ver = (
                (r.stdout or r.stderr or b"")
                .decode(errors="ignore")
                .strip()
                .split("\n")[0]
            )
            print(f"       Version: {ver}")
        except Exception as e:
            print(f"  [WARN] Cannot run mihomo -v: {e}")
    else:
        print(f"  [FAIL] Mihomo NOT found: {mp}")
        ok = False

    # 4. Тест парсера
    test_uri = "vless://12345678-1234-1234-1234-123456789abc@1.2.3.4:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&type=tcp&flow=xtls-rprx-vision#test"
    result = parse_to_mihomo(test_uri)
    if result:
        print(
            f"  [OK] Parser works: {result.get('type')} server={result.get('server')}"
        )
    else:
        print("  [FAIL] Parser returned None for test VLESS URI")
        ok = False

    # 5. Тест запуска mihomo (если есть)
    if mp.exists():
        test_port = 29999
        test_struct = result or {
            "type": "ss",
            "server": "1.1.1.1",
            "port": 443,
            "cipher": "aes-256-gcm",
            "password": "test",
            "name": "test",
            "udp": False,
        }
        test_struct["name"] = "test_probe"
        cfg = make_mihomo_config(test_struct, "test_probe", test_port)
        cfg_p = TMP_DIR / "selftest.json"
        with open(cfg_p, "w") as f:
            json.dump(cfg, f)
        # FIX #9: читаем stdout ДО kill, иначе communicate() после wait() всегда b""
        proc = subprocess.Popen(
            [str(mp), "-f", str(cfg_p)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        started = wait_for_port(test_port, max_wait=4.0)
        # Читаем вывод сразу если процесс уже умер
        out = b""
        if proc.poll() is not None:
            try:
                out = proc.stdout.read() if proc.stdout else b""
            except Exception:
                pass
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
        cfg_p.unlink(missing_ok=True)
        if started:
            print(f"  [OK] Mihomo starts and binds port {test_port}")
        else:
            msg = out.decode(errors="ignore").strip()[-300:] if out else "no output"
            print(f"  [FAIL] Mihomo did not start. Output: {msg}")
            ok = False

    if not ok:
        sys.exit("\n[ABORT] Self-test failed. Fix the issues above and retry.")
    print("  All checks passed!\n")


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
            "check_speed": args.speed,
            "min_speed_mbps": args.min_speed,
            "speed_max_mb": args.speed_max_mb,
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

    # Определяем реальный IP машины — для проверки IP leak
    global REAL_IP
    print("\n🔍 Определяю реальный IP...")
    REAL_IP = detect_real_ip()
    if REAL_IP:
        print(f"   Реальный IP: {REAL_IP} (ключи с этим IP будут отбракованы)")
    else:
        print("   ⚠️  Не удалось определить реальный IP — IP leak проверка отключена")

    # Самодиагностика
    print("\n[Self-test]")
    self_test()

    # ════════════════════════════════════════════════════════════
    # РЕЖИМ 2: --speed-only
    # Загружаем уже проверенные ключи, замеряем скорость, обновляем файлы.
    # ════════════════════════════════════════════════════════════
    if args.speed_only:
        CFG["check_speed"] = True
        working = load_working_from_file()
        working = speed_pass(working)
        if not working:
            print("⚠️  Нет ключей для speed pass")
            return
        save_results(working)
        print("\n✅ Speed pass завершён!")
        return

    # ════════════════════════════════════════════════════════════
    # РЕЖИМ 1: БАЗОВАЯ ПРОВЕРКА (по умолчанию)
    # ════════════════════════════════════════════════════════════
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

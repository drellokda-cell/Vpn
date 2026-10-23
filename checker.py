#!/usr/bin/env python3
"""
Конвейер проверки конфигов (один запуск xray на конфиг):

  sources.txt -> сбор -> TCP-предфильтр (дешёвый)
    -> ЭТАП 1: HTTP через туннель (два 204-эндпоинта, реальная задержка)   -> 1test_config.txt
    -> ЭТАП 2: панель сайтов из targets.txt (>= порога) + замер скорости   -> 2test_config.txt
  Подробности по каждому конфигу: results.csv

Поддерживаются ссылки vless:// vmess:// trojan:// ss://
Нужны бинарник xray (PATH или XRAY_BIN) и curl.
"""
import asyncio
import base64
import csv
import json
import os
import random
import re
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from urllib.parse import urlparse, parse_qs, unquote

# ---------- настройки (всё меняется через переменные окружения) ----------
SOURCES_FILE = os.getenv("SOURCES_FILE", "sources.txt")
TARGETS_FILE = os.getenv("TARGETS_FILE", "targets.txt")
OUT_1 = os.getenv("OUT_1", "1test_config.txt")
OUT_2 = os.getenv("OUT_2", "2test_config.txt")
OUT_CSV = os.getenv("OUT_CSV", "results.csv")

PER_SOURCE_LIMIT = int(os.getenv("PER_SOURCE_LIMIT", "600"))   # сколько брать с одного источника
TCP_TIMEOUT = float(os.getenv("TCP_TIMEOUT", "4"))
TCP_CONCURRENCY = int(os.getenv("TCP_CONCURRENCY", "300"))
MAX_STAGE1 = int(os.getenv("MAX_STAGE1", "1500"))              # сколько конфигов пускать в xray

WORKERS = int(os.getenv("WORKERS", "16"))                      # параллельных xray-процессов
BASE_PORT = int(os.getenv("BASE_PORT", "21000"))
XRAY_BIN = os.getenv("XRAY_BIN", "xray")
PROBE_TIMEOUT = int(os.getenv("PROBE_TIMEOUT", "8"))           # секунд на один URL
PANEL_PARALLEL = int(os.getenv("PANEL_PARALLEL", "4"))         # одновременных запросов панели на конфиг
PANEL_THRESHOLD = float(os.getenv("PANEL_THRESHOLD", "0.7"))   # доля сайтов панели, которые должны открыться

DL_URL = os.getenv("DL_URL", "https://speed.cloudflare.com/__down?bytes=41943040")  # 40 МБ
DL_TIMEOUT = int(os.getenv("DL_TIMEOUT", "30"))                # макс. секунд на загрузку
MIN_BYTES = int(os.getenv("MIN_BYTES", str(10 * 1024 * 1024))) # сколько минимум должно скачаться
MIN_MBPS = float(os.getenv("MIN_MBPS", "3"))                   # минимальная средняя скорость, Мбит/с
SPEED_WORKERS = int(os.getenv("SPEED_WORKERS", "3"))           # одновременных загрузок (чтобы не душить канал)
MAX_SPEED = int(os.getenv("MAX_SPEED", "200"))                 # максимум конфигов на замер скорости

# 204-эндпоинты для этапа 1: оба должны ответить ровно 204 без тела
STAGE1_URLS = ["https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"]
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"

# панель по умолчанию: (url, допустимые коды, мин. размер тела). Свою можно задать в targets.txt
DEFAULT_PANEL = [
    ("https://www.google.com/", {200}, 1000),
    ("https://www.youtube.com/", {200}, 1000),
    ("https://www.instagram.com/", {200}, 1000),
    ("https://web.telegram.org/", {200}, 500),
    ("https://discord.com/", {200}, 1000),
    ("https://github.com/", {200}, 1000),
    ("https://www.wikipedia.org/", {200}, 1000),
]

LINK_RE = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>]+")


def load_panel() -> list:
    """targets.txt: 'URL [коды через запятую] [мин_размер]', # - комментарий."""
    if not os.path.exists(TARGETS_FILE):
        return DEFAULT_PANEL
    panel = []
    with open(TARGETS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            p = line.split()
            codes = {int(c) for c in p[1].split(",")} if len(p) > 1 else {200}
            size = int(p[2]) if len(p) > 2 else 500
            panel.append((p[0], codes, size))
    return panel or DEFAULT_PANEL


# ---------- сбор ----------
def b64d(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        text = r.read().decode("utf-8", "ignore")
    if "://" not in text:  # возможно, подписка в base64
        try:
            text = b64d(text)
        except Exception:
            pass
    return text


def load_sources() -> list:
    with open(SOURCES_FILE, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


# ---------- парсинг ссылок в outbound для xray ----------
def make_stream(net, security, q, host_fallback):
    net = net or "tcp"
    if net not in ("tcp", "ws", "grpc", "httpupgrade"):
        raise ValueError(f"unsupported transport {net}")
    s = {"network": net}
    sni = q.get("sni") or q.get("host") or host_fallback
    fp = q.get("fp") or "chrome"
    if security == "tls":
        s["security"] = "tls"
        s["tlsSettings"] = {"serverName": sni, "fingerprint": fp}
        if q.get("alpn"):
            s["tlsSettings"]["alpn"] = q["alpn"].split(",")
    elif security == "reality":
        s["security"] = "reality"
        s["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fp,
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", ""),
        }
    if net == "ws":
        s["wsSettings"] = {"path": q.get("path", "/"),
                           "headers": {"Host": q.get("host") or sni}}
    elif net == "grpc":
        s["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
    elif net == "httpupgrade":
        s["httpupgradeSettings"] = {"path": q.get("path", "/"),
                                    "host": q.get("host") or sni}
    return s


def parse_link(link: str):
    """Возвращает dict(host, port, outbound, key) или None."""
    try:
        u = urlparse(link)
        scheme = u.scheme
        if scheme == "vmess":
            j = json.loads(b64d(link[len("vmess://"):]))
            host, port = j["add"], int(j["port"])
            q = {"host": j.get("host", ""), "path": j.get("path", "/"),
                 "sni": j.get("sni", ""), "serviceName": j.get("path", "")}
            sec = "tls" if j.get("tls") == "tls" else ""
            ob = {"protocol": "vmess",
                  "settings": {"vnext": [{"address": host, "port": port, "users": [{
                      "id": j["id"], "alterId": int(j.get("aid", 0) or 0),
                      "security": j.get("scy", "auto")}]}]},
                  "streamSettings": make_stream(j.get("net", "tcp"), sec, q, host)}
            return {"host": host, "port": port, "outbound": ob, "key": f"vmess|{host}|{port}|{j['id']}"}

        if scheme == "ss":
            body = link[len("ss://"):].split("#")[0].split("?")[0]
            if "@" in body:
                userinfo, hp = body.rsplit("@", 1)
                try:
                    method, pwd = b64d(userinfo).split(":", 1)
                except Exception:
                    method, pwd = unquote(userinfo).split(":", 1)
            else:
                dec = b64d(body)
                userinfo, hp = dec.rsplit("@", 1)
                method, pwd = userinfo.split(":", 1)
            host, port = hp.rsplit(":", 1)
            port = int(port)
            ob = {"protocol": "shadowsocks",
                  "settings": {"servers": [{"address": host, "port": port,
                                            "method": method, "password": pwd}]}}
            return {"host": host, "port": port, "outbound": ob, "key": f"ss|{host}|{port}|{pwd}"}

        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        host, port = u.hostname, u.port
        if not host or not port:
            return None
        sec = q.get("security", "")
        stream = make_stream(q.get("type", "tcp"), sec, q, host)
        if scheme == "vless":
            user = {"id": u.username, "encryption": q.get("encryption", "none")}
            if q.get("flow"):
                user["flow"] = q["flow"]
            ob = {"protocol": "vless",
                  "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
                  "streamSettings": stream}
            return {"host": host, "port": port, "outbound": ob, "key": f"vless|{host}|{port}|{u.username}"}
        if scheme == "trojan":
            ob = {"protocol": "trojan",
                  "settings": {"servers": [{"address": host, "port": port,
                                            "password": unquote(u.username)}]},
                  "streamSettings": stream}
            return {"host": host, "port": port, "outbound": ob, "key": f"trojan|{host}|{port}|{u.username}"}
    except Exception:
        return None
    return None


def collect() -> list:
    items, seen = [], set()
    for src in load_sources():
        try:
            links = LINK_RE.findall(fetch(src))
            random.shuffle(links)  # не брать всегда одни и те же верхние строки
        except Exception as e:
            print(f"[!] не скачался {src}: {e}")
            continue
        taken = 0
        for link in links:
            if taken >= PER_SOURCE_LIMIT:
                break
            info = parse_link(link.strip())
            if not info or info["key"] in seen:
                continue
            seen.add(info["key"])
            info["link"] = link.strip()
            items.append(info)
            taken += 1
        print(f"[+] {src}: взято {taken} из {len(links)}")
    return items


# ---------- этап 0: TCP-предфильтр ----------
# Это только отсев совсем мёртвых портов. Серверы за CDN (Cloudflare и т.п.) принимают
# TCP почти всегда, поэтому настоящая проверка - только через туннель (этап 1).
async def tcp_check(items: list) -> list:
    sem = asyncio.Semaphore(TCP_CONCURRENCY)

    async def one(it):
        async with sem:
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(it["host"], it["port"]), TCP_TIMEOUT)
                w.close()
                return it
            except Exception:
                return None

    res = await asyncio.gather(*(one(i) for i in items))
    return [r for r in res if r]


# ---------- проверки через туннель ----------
def wait_port(port: int, proc, timeout=6.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def curl(port: int, url: str, timeout: int, want_body=False):
    """Запрос через SOCKS xray. Возвращает (код, размер, время_с, тело|None, rc)."""
    cmd = ["curl", "-s", "-L", "--max-redirs", "3", "-A", "Mozilla/5.0",
           "--socks5-hostname", f"127.0.0.1:{port}", "--max-time", str(timeout),
           "-o", "-" if want_body else "/dev/null",
           "-w", "\n%{http_code} %{size_download} %{time_total}", url]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        out = r.stdout
        body, _, tail = out.rpartition("\n")
        code, size, t = tail.split()
        return int(code), int(float(size)), float(t), (body if want_body else None), r.returncode
    except Exception:
        return 0, 0, 0.0, None, -1


def stage1_check(port: int):
    """Оба 204-эндпоинта должны вернуть ровно 204 и пустое тело. -> задержка мс или None."""
    times = []
    for url in STAGE1_URLS:
        code, size, t, _, rc = curl(port, url, PROBE_TIMEOUT)
        if rc != 0 or code != 204 or size != 0:
            return None
        times.append(t)
    return round(sum(times) / len(times) * 1000)


def exit_country(port: int) -> str:
    code, _, _, body, rc = curl(port, TRACE_URL, PROBE_TIMEOUT, want_body=True)
    if rc == 0 and body:
        m = re.search(r"^loc=(\w+)", body, re.M)
        if m:
            return m.group(1)
    return "??"


def panel_check(port: int, panel: list):
    """Открываем каждый сайт панели. -> (сколько открылось, список упавших URL)."""
    def one(t):
        url, codes, min_size = t
        code, size, _, _, rc = curl(port, url, PROBE_TIMEOUT)
        return url if (rc != 0 or code not in codes or size < min_size) else None

    with ThreadPoolExecutor(PANEL_PARALLEL) as ex:
        failed = [u for u in ex.map(one, panel) if u]
    return len(panel) - len(failed), failed


def speed_check(port: int):
    """Скачивание через туннель. -> Мбит/с или None. Таймаут не считается провалом сам по себе:
    важно, сколько успело скачаться и с какой средней скоростью."""
    code, size, t, _, rc = curl(port, DL_URL, DL_TIMEOUT)
    if rc not in (0, 28) or code != 200 or t <= 0 or size < MIN_BYTES:
        return None
    mbps = size * 8 / t / 1e6
    return round(mbps, 1) if mbps >= MIN_MBPS else None


def run_session(it: dict, port: int, panel: list, speed_sem, speed_budget):
    """Один запуск xray на конфиг: этап 1 -> панель -> скорость."""
    cfg = {"log": {"loglevel": "none"},
           "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                         "settings": {"udp": False}}],
           "outbounds": [it["outbound"]]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        path = f.name
    proc = subprocess.Popen([XRAY_BIN, "run", "-c", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port(port, proc):
            return it
        delay = stage1_check(port)
        if delay is None:
            return it
        it["stage1"] = True
        it["delay_ms"] = delay
        it["country"] = exit_country(port)

        ok, failed = panel_check(port, panel)
        it["panel_ok"], it["panel_total"], it["panel_failed"] = ok, len(panel), failed
        if ok / len(panel) < PANEL_THRESHOLD:
            return it

        with speed_sem:
            with speed_budget["lock"]:
                if speed_budget["left"] <= 0:
                    return it
                speed_budget["left"] -= 1
            mbps = speed_check(port)
        if mbps:
            it["stage2"] = True
            it["mbps"] = mbps
        return it
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        os.unlink(path)


def test_all(items: list, panel: list) -> list:
    ports = Queue()
    for i in range(WORKERS):
        ports.put(BASE_PORT + i)
    speed_sem = threading.Semaphore(SPEED_WORKERS)
    speed_budget = {"left": MAX_SPEED, "lock": threading.Lock()}
    done = {"n": 0}

    def job(it):
        port = ports.get()
        try:
            res = run_session(it, port, panel, speed_sem, speed_budget)
        finally:
            ports.put(port)
        done["n"] += 1
        if res.get("stage2"):
            print(f"  [{done['n']}/{len(items)}] OK  {res['host']}:{res['port']} "
                  f"{res['country']} {res['delay_ms']}ms {res['mbps']}Мбит/с "
                  f"панель {res['panel_ok']}/{res['panel_total']}")
        return res

    with ThreadPoolExecutor(WORKERS) as ex:
        return list(ex.map(job, items))


# ---------- вывод ----------
def write_list(path: str, items: list):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(i["link"] for i in items) + "\n")


def write_csv(path: str, items: list):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["proto", "host", "port", "country", "delay_ms", "panel", "mbps", "stage2", "failed_sites"])
        for i in items:
            w.writerow([i["key"].split("|")[0], i["host"], i["port"], i.get("country", ""),
                        i.get("delay_ms", ""), f"{i.get('panel_ok', 0)}/{i.get('panel_total', 0)}",
                        i.get("mbps", ""), int(bool(i.get("stage2"))), " ".join(i.get("panel_failed", []))])


def main():
    panel = load_panel()
    items = collect()
    print(f"Всего уникальных конфигов: {len(items)}; сайтов в панели: {len(panel)}")
    if not items:
        print("Нечего проверять - файлы не трогаем.")
        return

    alive = asyncio.run(tcp_check(items))
    print(f"TCP-предфильтр: {len(alive)} из {len(items)}")
    random.shuffle(alive)
    alive = alive[:MAX_STAGE1]

    results = test_all(alive, panel)
    s1 = sorted((r for r in results if r.get("stage1")), key=lambda x: x["delay_ms"])
    s2 = sorted((r for r in results if r.get("stage2")),
                key=lambda x: (-x["panel_ok"], -x["mbps"]))
    print(f"Этап 1 (HTTP через туннель): {len(s1)} из {len(alive)}")
    print(f"Этап 2 (панель + скорость):  {len(s2)} из {len(s1)}")

    # пустым результатом при сбое сети старые файлы не затираем
    if s1:
        write_list(OUT_1, s1)
        write_csv(OUT_CSV, s1)
    if s2:
        write_list(OUT_2, s2)


if __name__ == "__main__":
    main()

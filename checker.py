#!/usr/bin/env python3
"""
Конвейер проверки конфигов:
  sources.txt -> сбор -> TCP (1test_config.txt) -> загрузка файла через туннель xray (2test_config.txt)

Поддерживаются ссылки vless:// vmess:// trojan:// ss://
Для этапа 2 нужен бинарник xray в PATH (или XRAY_BIN) и curl.
"""
import asyncio
import base64
import json
import os
import random
import re
import socket
import subprocess
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from urllib.parse import urlparse, parse_qs, unquote

# ---------- настройки (можно менять через переменные окружения) ----------
SOURCES_FILE = os.getenv("SOURCES_FILE", "sources.txt")
OUT_1 = os.getenv("OUT_1", "1test_config.txt")
OUT_2 = os.getenv("OUT_2", "2test_config.txt")

PER_SOURCE_LIMIT = int(os.getenv("PER_SOURCE_LIMIT", "300"))   # сколько брать с одного источника
TCP_TIMEOUT = float(os.getenv("TCP_TIMEOUT", "4"))
TCP_CONCURRENCY = int(os.getenv("TCP_CONCURRENCY", "200"))

DL_URL = os.getenv("DL_URL", "https://speed.cloudflare.com/__down?bytes=41943040")  # 40 МБ
DL_BYTES = int(os.getenv("DL_BYTES", "41943040"))
DL_TIMEOUT = int(os.getenv("DL_TIMEOUT", "40"))        # макс. секунд на одну загрузку
MAX_STAGE2 = int(os.getenv("MAX_STAGE2", "300"))       # сколько конфигов отправлять на этап 2
WORKERS = int(os.getenv("WORKERS", "8"))               # параллельных xray-процессов
BASE_PORT = int(os.getenv("BASE_PORT", "21000"))
XRAY_BIN = os.getenv("XRAY_BIN", "xray")

LINK_RE = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>]+")


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


# ---------- этап 1: TCP ----------
async def tcp_check(items: list) -> list:
    sem = asyncio.Semaphore(TCP_CONCURRENCY)

    async def one(it):
        async with sem:
            t = time.perf_counter()
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(it["host"], it["port"]), TCP_TIMEOUT)
                w.close()
                it["tcp_ms"] = round((time.perf_counter() - t) * 1000)
                return it
            except Exception:
                return None

    res = await asyncio.gather(*(one(i) for i in items))
    return sorted((r for r in res if r), key=lambda x: x["tcp_ms"])


# ---------- этап 2: загрузка через туннель ----------
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


def tunnel_download(it: dict, port: int):
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
            return None
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "--socks5-hostname", f"127.0.0.1:{port}",
             "--max-time", str(DL_TIMEOUT), "-w", "%{size_download} %{speed_download}", DL_URL],
            capture_output=True, text=True)
        if r.returncode != 0:
            return None
        size, speed = r.stdout.split()
        if int(float(size)) >= DL_BYTES:
            return float(speed)  # байт/сек
        return None
    except Exception:
        return None
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        os.unlink(path)


def download_stage(items: list) -> list:
    ports = Queue()
    for i in range(WORKERS):
        ports.put(BASE_PORT + i)

    def job(it):
        port = ports.get()
        try:
            speed = tunnel_download(it, port)
        finally:
            ports.put(port)
        if speed:
            it["mbps"] = round(speed * 8 / 1e6, 1)
            print(f"  OK  {it['host']}:{it['port']}  {it['mbps']} Мбит/с")
            return it
        return None

    with ThreadPoolExecutor(WORKERS) as ex:
        res = list(ex.map(job, items))
    return sorted((r for r in res if r), key=lambda x: -x["mbps"])


# ---------- вывод ----------
def write_list(path: str, items: list):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(i["link"] for i in items) + "\n")


def main():
    items = collect()
    print(f"Всего уникальных конфигов: {len(items)}")
    if not items:
        print("Нечего проверять — файлы не трогаем.")
        return

    passed1 = asyncio.run(tcp_check(items))
    print(f"Этап 1 (TCP): {len(passed1)} из {len(items)}")
    if passed1:  # не затираем файл пустым результатом при сбое сети
        write_list(OUT_1, passed1)

    stage2_in = passed1[:MAX_STAGE2]
    random.shuffle(stage2_in)
    passed2 = download_stage(stage2_in)
    print(f"Этап 2 (загрузка): {len(passed2)} из {len(stage2_in)}")
    if passed2:
        write_list(OUT_2, passed2)


if __name__ == "__main__":
    main()

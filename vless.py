#!/usr/bin/env python3
 

import requests
import re
import time
import socket
import json
import os
import sys
import ssl
import statistics
import threading
from urllib.parse import unquote
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ──────────────────────────────────────────────
#  НАСТРОЙКИ
# ──────────────────────────────────────────────
SOURCES = [
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/clean/vless.txt",  # было vless.tx — исправлено
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/protocols/vless.txt",
]

THREADS         = 60      # параллельных потоков при проверке ключей
FETCH_THREADS   = 7       # потоков для загрузки источников
BATCH           = 100     # ключей за один батч
PING_TIMEOUT    = 3       # сек — TCP-таймаут
PING_REPEATS    = 3       # замеров пинга (берём медиану)
MIN_SCORE       = 2       # минимальный балл для сохранения
TOP_N           = 20      # сколько «топ» ключей вывести в итоге
GEO_RETRIES     = 2       # повторов при rate-limit GeoIP
SAVE_FILE       = os.path.expanduser("~/vless_progress.json")
ALIVE_FILE      = os.path.expanduser("~/vless_working.txt")
REPORT_FILE     = os.path.expanduser("~/vless_report.txt")

geo_cache: dict = {}
geo_lock = threading.Lock()

# ──────────────────────────────────────────────
#  ПАРСИНГ
# ──────────────────────────────────────────────
def parse_vless(key: str) -> dict | None:
    try:
        original = key.strip()
        s = original.replace("vless://", "")
        name = "N/A"
        if "#" in s:
            s, name = s.rsplit("#", 1)
            name = unquote(name).strip()[:60]
        if "@" not in s:
            return None
        uuid, rest = s.split("@", 1)
        if len(uuid) < 8:
            return None
        params_str = ""
        if "?" in rest:
            host_port, params_str = rest.split("?", 1)
        else:
            host_port = rest
        # IPv6: [2001:db8::1]:443  →  host="2001:db8::1"  port="443"
        if host_port.startswith("["):
            bracket_end = host_port.find("]")
            if bracket_end == -1:
                return None
            host = host_port[1:bracket_end]
            after = host_port[bracket_end + 1:]
            port = after.lstrip(":").split("/")[0] if ":" in after else "443"
        elif ":" in host_port:
            host, port = host_port.rsplit(":", 1)
            port = port.split("/")[0]
        else:
            host, port = host_port, "443"
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            return None
        params: dict = {}
        for p in params_str.split("&"):
            if "=" in p:
                k, v = p.split("=", 1)
                params[k.strip()] = unquote(v).strip()
        return {
            "uuid":       uuid,
            "uuid_short": uuid[:8] + "...",
            "host":       host,
            "port":       port,
            "name":       name,
            "security":   params.get("security", "none"),
            "type":       params.get("type", "tcp"),
            "sni":        params.get("sni", host),
            "fp":         params.get("fp", ""),
            "pbk":        params.get("pbk", ""),
            "sid":        params.get("sid", ""),
            "alpn":       params.get("alpn", ""),
            "original":   original,
        }
    except Exception:
        return None


def dedup_key(info: dict) -> str:
    """Ключ дедупликации: uuid + host + port (игнорируем имя/параметры)."""
    return f"{info['uuid']}@{info['host']}:{info['port']}"


# ──────────────────────────────────────────────
#  ПИНГ (медиана нескольких замеров)
# ──────────────────────────────────────────────
def ping_host(host: str, port: str, timeout: int = PING_TIMEOUT) -> tuple[int | None, str]:
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None, "N/A"

    samples = []
    for _ in range(PING_REPEATS):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)
            start = time.time()
            s.connect((ip, int(port)))
            samples.append(int((time.time() - start) * 1000))
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(0.05)

    if not samples:
        return None, ip
    return int(statistics.median(samples)), ip


# ──────────────────────────────────────────────
#  TLS-ПРОВЕРКА
# ──────────────────────────────────────────────
def check_tls(host: str, port: str, sni: str, timeout: int = 3) -> bool:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = socket.create_connection((host, int(port)), timeout=timeout)
        conn.settimeout(timeout)
        with ctx.wrap_socket(conn, server_hostname=sni if sni else host):
            return True
    except Exception:
        return False


# ──────────────────────────────────────────────
#  GEOIP (с повтором при rate-limit)
# ──────────────────────────────────────────────
def geoip(ip: str) -> str:
    for attempt in range(GEO_RETRIES):
        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org",
                timeout=4,
            )
            if r.status_code == 429:
                time.sleep(2 * (attempt + 1))   # экспоненциальная пауза
                continue
            d = r.json()
            if d.get("status") == "success":
                isp = (d.get("org") or d.get("isp") or "?")[:25]
                return f"{d.get('countryCode','?')} | {d.get('city','?')} | {isp}"
        except Exception:
            pass
    return "N/A"


# ──────────────────────────────────────────────
#  ОЦЕНКА КЛЮЧА (0–11 баллов)
#  пинг(4) + security(3) + tls(1) + fp(1) + transport(1) + sni(1)
# ──────────────────────────────────────────────
def score_key(ping_ms: int | None, info: dict, tls_ok: bool) -> tuple[int, str]:
    if ping_ms is None:
        return 0, "💀 DEAD"

    score = 0

    if ping_ms < 80:
        score += 4
    elif ping_ms < 200:
        score += 3
    elif ping_ms < 400:
        score += 2
    elif ping_ms < 700:
        score += 1

    sec = info["security"].lower()
    if sec == "reality":
        score += 3
    elif sec == "tls":
        score += 2

    if tls_ok:
        score += 1
    if info.get("fp"):
        score += 1
    if info["type"].lower() in ("ws", "grpc"):
        score += 1
    if info.get("sni") and info["sni"] != info["host"]:
        score += 1

    if score >= 9:
        return score, "⭐⭐⭐ Отличный"
    elif score >= 6:
        return score, "⭐⭐  Хороший"
    elif score >= 3:
        return score, "⭐   Средний"
    elif score >= 1:
        return score, "·    Слабый"
    else:
        return score, "💀   DEAD"


# ──────────────────────────────────────────────
#  ПРОВЕРКА ОДНОГО КЛЮЧА
# ──────────────────────────────────────────────
def check_one(key: str) -> dict | None:
    info = parse_vless(key)
    if info is None:
        return None

    ping_ms, ip = ping_host(info["host"], info["port"])

    geo = "N/A"
    if ip and ip != "N/A":
        with geo_lock:
            if ip not in geo_cache:
                geo_cache[ip] = None
        fetched = geoip(ip)
        with geo_lock:
            if geo_cache.get(ip) is None:
                geo_cache[ip] = fetched
            geo = geo_cache[ip] or "N/A"

    tls_ok = False
    if ping_ms is not None and info["security"] in ("tls", "reality"):
        tls_ok = check_tls(info["host"], info["port"], info["sni"])

    score, rating = score_key(ping_ms, info, tls_ok)

    return {
        "info":     info,
        "ping_ms":  ping_ms,
        "ip":       ip,
        "geo":      geo,
        "tls_ok":   tls_ok,
        "score":    score,
        "rating":   rating,
        "sort_val": ping_ms if ping_ms is not None else 9999,
    }


# ──────────────────────────────────────────────
#  БАТЧ с ETA
# ──────────────────────────────────────────────
def check_batch(keys_batch: list) -> list:
    results = []
    done = [0]
    total = len(keys_batch)
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(check_one, k): k for k in keys_batch}
        for future in as_completed(futures):
            done[0] += 1
            pct = int(done[0] * 100 / total)
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)

            elapsed = time.time() - start_time
            eta_sec = int(elapsed / done[0] * (total - done[0]))
            eta_str = f"ETA {eta_sec}с"

            print(f"  [{bar}] {pct:3d}% ({done[0]}/{total}) {eta_str}   ", end="\r")
            try:
                r = future.result()
                if r is not None:
                    results.append(r)
            except Exception:
                pass

    results.sort(key=lambda x: (-x["score"], x["sort_val"]))
    return results


# ──────────────────────────────────────────────
#  ВЫВОД КАРТОЧКИ
# ──────────────────────────────────────────────
def print_card(r: dict, num: int):
    info = r["info"]
    ping_str = f"{r['ping_ms']} ms" if r["ping_ms"] is not None else "недоступен"
    tls_str  = "да" if r["tls_ok"] else "нет"
    sep = "-" * 52
    print(f"\n{sep}")
    print(f"  #{num:03d}  {info['name'][:44]}")
    print(sep)
    print(f"  Хост:      {info['host']}")
    print(f"  Порт:      {info['port']}")
    print(f"  Security:  {info['security']}")
    print(f"  Тип:       {info['type']}")
    print(f"  SNI:       {info['sni'][:50]}")
    print(f"  Пинг:      {ping_str}")
    print(f"  TLS:       {tls_str}")
    print(f"  Гео:       {r['geo'][:50]}")
    print(f"  Балл:      {r['score']}/11  {r['rating']}")
    print(sep)


# ──────────────────────────────────────────────
#  СТАТИСТИКА БАТЧА
# ──────────────────────────────────────────────
def print_batch_stats(results: list):
    alive  = [r for r in results if r["ping_ms"] is not None]
    dead   = [r for r in results if r["ping_ms"] is None]
    worthy = [r for r in alive if r["score"] >= MIN_SCORE]

    print(f"\n  Всего:     {len(results)}")
    print(f"  Живых:     {len(alive)}  ({int(len(alive)*100/max(len(results),1))}%)")
    print(f"  Мёртвых:   {len(dead)}")
    print(f"  Качеств.:  {len(worthy)} (score ≥ {MIN_SCORE})")

    if alive:
        pings = [r["ping_ms"] for r in alive]
        print(f"  Мин.пинг:  {min(pings)} ms")
        print(f"  Медиана:   {int(statistics.median(pings))} ms")
        print(f"  Макс.пинг: {max(pings)} ms")

    sec_counts: dict = defaultdict(int)
    for r in alive:
        sec_counts[r["info"]["security"]] += 1
    if sec_counts:
        print("  Security:  " + "  ".join(f"{k}={v}" for k, v in sec_counts.items()))


# ──────────────────────────────────────────────
#  СОХРАНЕНИЕ
# ──────────────────────────────────────────────
def save_progress(all_keys: list, index: int):
    with open(SAVE_FILE, "w", encoding="utf-8") as f:
        json.dump({"keys": all_keys, "index": index,
                   "saved_at": datetime.now().isoformat()}, f, ensure_ascii=False)


def load_progress() -> tuple[list | None, int]:
    if not os.path.exists(SAVE_FILE):
        return None, 0
    try:
        with open(SAVE_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d["keys"], d["index"]
    except Exception:
        return None, 0


def save_all_alive(all_alive: list):
    scored = [r for r in all_alive if r["ping_ms"] != 0]
    pool   = scored if scored else all_alive
    srt    = sorted(pool, key=lambda x: (-x["score"], x["sort_val"]))

    lines = [
        "# VLESS Working Keys — отсортировано по качеству",
        f"# Обновлено: {datetime.now().strftime('%H:%M:%S %d.%m.%Y')}",
        f"# Всего: {len(srt)}",
        "#",
        "# [балл/11] | пинг | гео | security",
        "# vless://ключ",
        "",
    ]

    current_label = None
    for r in srt:
        info = r["info"]
        ping = f"{r['ping_ms']} ms" if r["ping_ms"] is not None and r["ping_ms"] != 0 else "?"
        if r["rating"] != current_label:
            current_label = r["rating"]
            lines += [
                "",
                f"# {'─'*52}",
                f"# {current_label}",
                f"# {'─'*52}",
            ]
        lines.append(
            f"# [{r['score']:2d}/11] | {ping:>7} | {r['geo'][:35]} | {info['security']}"
        )
        lines.append(info["original"])

    with open(ALIVE_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def save_report(all_alive: list):
    scored = [r for r in all_alive if r["ping_ms"] != 0]
    pool = scored if scored else all_alive
    top = sorted(pool, key=lambda x: (-x["score"], x["sort_val"]))[:TOP_N]
    lines = [
        "=" * 60,
        f"  VLESS REPORT — {datetime.now().strftime('%d.%m.%Y %H:%M')}",
        f"  Всего рабочих: {len(all_alive)}  |  Топ-{TOP_N} ниже",
        "=" * 60,
        "",
    ]
    for i, r in enumerate(top, 1):
        info = r["info"]
        lines += [
            f"#{i:02d}  [{r['score']:2d}/11] {r['rating']}",
            f"    Хост: {info['host']}:{info['port']}  ({info['security']} / {info['type']})",
            f"    Гео:  {r['geo']}   Пинг: {r['ping_ms']} ms",
            f"    {info['original'][:80]}",
            "",
        ]
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n  📄 Отчёт сохранён: {REPORT_FILE}")


# ──────────────────────────────────────────────
#  ЗАГРУЗКА КЛЮЧЕЙ (параллельная)
# ──────────────────────────────────────────────
def fetch_keys(url: str) -> tuple[str, list]:
    """Возвращает (url, список_ключей). При ошибке список пустой."""
    fname = url.split("/")[-1]
    try:
        r = requests.get(url, timeout=12)
        r.raise_for_status()
        r.encoding = "utf-8"
        keys = re.findall(r'vless://[^\s\'\"<>\]\[]+', r.text)
        unique = list(set(keys))
        return url, unique
    except requests.HTTPError as e:
        print(f"\n  ⚠ HTTP {e.response.status_code} — {fname}")
        return url, []
    except Exception as e:
        print(f"\n  ⚠ Ошибка загрузки {fname}: {e}")
        return url, []


def fetch_all_sources() -> tuple[list, dict]:
    """Загружает все источники параллельно, возвращает (все_ключи, статистика)."""
    print("\n  Загружаю ключи из источников (параллельно)...")
    key_set: set = set()
    source_stats: dict = {}  # url → кол-во ключей

    with ThreadPoolExecutor(max_workers=FETCH_THREADS) as executor:
        futures = {executor.submit(fetch_keys, url): url for url in SOURCES}
        for future in as_completed(futures):
            url, keys = future.result()
            fname = url.split("/")[-1]
            before = len(key_set)
            key_set.update(keys)
            new_unique = len(key_set) - before
            source_stats[fname] = {"total": len(keys), "new_unique": new_unique}
            status = f"{len(keys)} ключей (+{new_unique} новых)"
            print(f"  ✓ {fname[:45]:<45} {status}")

    return list(key_set), source_stats


# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────
def main():
    print("=" * 54)
    print("  VLESS KEY CHECKER  v2.1")
    print(f"  {datetime.now().strftime('%H:%M:%S  %d.%m.%Y')}")
    print(f"  Потоков: {THREADS}  |  Батч: {BATCH}  |  Min.score: {MIN_SCORE}/11")
    print(f"  Источников: {len(SOURCES)}")
    print("=" * 54)

    # ── прогресс ──
    saved_keys, saved_index = load_progress()
    if saved_keys and saved_index > 0:
        print(f"\n  Найден прогресс: проверено {saved_index}/{len(saved_keys)}")
        ans = input("  Продолжить? (Enter / n): ").strip().lower()
        if ans in ("", "y", "yes"):
            all_keys, current_index = saved_keys, saved_index
        else:
            all_keys, current_index = None, 0
    else:
        all_keys, current_index = None, 0

    # ── загрузка ──
    if all_keys is None:
        all_keys, _ = fetch_all_sources()

        # Дедупликация по uuid+host+port (более умная)
        seen_dedup: set = set()
        deduped = []
        for k in all_keys:
            info = parse_vless(k)
            if info is None:
                continue
            dk = dedup_key(info)
            if dk not in seen_dedup:
                seen_dedup.add(dk)
                deduped.append(k)
        all_keys = deduped

        current_index = 0
        save_progress(all_keys, 0)

        print(f"\n  {'─'*52}")
        print(f"  Итого уникальных ключей: {len(all_keys)}")
        print(f"  {'─'*52}")

        if os.path.exists(ALIVE_FILE):
            os.remove(ALIVE_FILE)

    total = len(all_keys)

    # ── загрузка живых из прошлой сессии ──
    all_alive: list = []
    if current_index > 0 and os.path.exists(ALIVE_FILE):
        try:
            with open(ALIVE_FILE, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("vless://"):
                        info = parse_vless(line)
                        if info:
                            all_alive.append({
                                "info":     info,
                                "ping_ms":  0,
                                "ip":       "N/A",
                                "geo":      "N/A",
                                "tls_ok":   False,
                                "score":    0,
                                "rating":   "(из прошлой сессии)",
                                "sort_val": 0,
                            })
            if all_alive:
                print(f"\n  Загружено из прошлой сессии: {len(all_alive)} живых ключей")
        except Exception:
            pass

    # ── основной цикл ──
    while current_index < total:
        batch_end = min(current_index + BATCH, total)
        batch_num = current_index // BATCH + 1

        print(f"\n{'═'*54}")
        print(f"  БАТЧ #{batch_num}  |  Ключи {current_index+1}–{batch_end} из {total}")
        print(f"{'═'*54}\n")

        batch = all_keys[current_index:batch_end]
        results = check_batch(batch)
        print()

        alive  = [r for r in results if r["ping_ms"] is not None]
        worthy = [r for r in alive if r["score"] >= MIN_SCORE]
        all_alive.extend(worthy)

        print_batch_stats(results)

        if worthy:
            print(f"\n  ── Рабочие (score ≥ {MIN_SCORE}) ──")
            for i, r in enumerate(worthy, 1):
                print_card(r, i)
            print(f"\n  ✓ {len(worthy)} ключей добавлено в {ALIVE_FILE}")
        else:
            print("\n  В этом батче качественных ключей нет.")

        if all_alive:
            save_all_alive(all_alive)

        current_index = batch_end
        save_progress(all_keys, current_index)

        if current_index >= total:
            break

        remaining_batches = (total - current_index + BATCH - 1) // BATCH
        print(f"\n  Осталось батчей: {remaining_batches}  |  ключей: {total - current_index}")
        print("  Enter = следующий батч  |  Ctrl+C = пауза")
        try:
            input("  Ваш выбор: ")
        except KeyboardInterrupt:
            print("\n\n  Остановлено. Прогресс сохранён.")
            print(f"  Запустите снова — продолжит с ключа #{current_index+1}")
            sys.exit(0)

    # ── финал ──
    print(f"\n{'═'*54}")
    print("  ВСЕ КЛЮЧИ ПРОВЕРЕНЫ!")
    print(f"  Рабочих (score ≥ {MIN_SCORE}): {len(all_alive)}")
    print(f"  Файл ключей: {ALIVE_FILE}")

    if all_alive:
        save_report(all_alive)
        scored = [r for r in all_alive if r["ping_ms"] != 0]
        pool = scored if scored else all_alive
        top = sorted(pool, key=lambda x: (-x["score"], x["sort_val"]))[:5]
        print(f"\n  ── ТОП-5 лучших ключей ──")
        for i, r in enumerate(top, 1):
            info = r["info"]
            print(f"  #{i}  [{r['score']:2d}/11] {info['host']}:{info['port']} "
                  f"| {info['security']} | {r['ping_ms']} ms | {r['geo']}")

    if os.path.exists(SAVE_FILE):
        os.remove(SAVE_FILE)

    print(f"\n  cat {ALIVE_FILE}")
    print(f"  cat {REPORT_FILE}")
    print("=" * 54)


if __name__ == "__main__":
    main()

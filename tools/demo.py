#!/usr/bin/env python3
"""Paneli denemek için ÖRNEK veri gönderir (gerçek ölçüm değildir).

Kullanım: tools/demo.py http://127.0.0.1:8080 nbt_... [tur sayısı]
Verilen şirket anahtarıyla üç sahte sunucu, bir ağ taraması, bir port taraması ve
SSH parola denemeleri raporlar. Üretim veritabanında çalıştırmayın."""
import json
import random
import sys
import time
import urllib.request

url, token = sys.argv[1].rstrip("/"), sys.argv[2]
rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 6
GB = 1024 ** 3
HOSTS = [("demo-db-01", "10.20.0.21", 91.0, 71), ("demo-app-02", "10.20.0.32", 54.0, 38), ("demo-fs-01", "10.20.0.11", 78.0, 14)]
DEVICES = [{"ip": "10.20.0.1", "mac": "02:de:00:00:00:01", "hostname": "demo-gw", "gateway": True, "iface": "eth0"}] + [
    {"ip": f"10.20.0.{100 + i}", "mac": f"02:de:00:00:01:{i:02x}", "hostname": name, "iface": "eth0"}
    for i, name in enumerate(["demo-yazici", "demo-kamera-1", "demo-kamera-2", "demo-ap-kat1", "demo-pc-muhasebe", ""])]


def send(payload):
    req = urllib.request.Request(url + "/api/agent/report", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
    urllib.request.urlopen(req, timeout=10).read()


for n in range(rounds):
    for i, (name, ip, disk, cpu) in enumerate(HOSTS):
        payload = {
            "agent_version": "demo", "capture_mode": "sniffer",
            "host": {"id": name, "hostname": name, "os": "Ubuntu 24.04 LTS (demo)", "ip": ip, "uptime_s": 4060800, "cores": 8},
            "metrics": {"cpu": cpu + random.uniform(-6, 6), "mem_pct": 60 + i * 8, "mem_used": int((38 + i * 5) * GB),
                        "mem_total": 64 * GB, "load1": 1.2, "rx_bps": random.randint(20, 90) * 10**6,
                        "tx_bps": random.randint(5, 30) * 10**6,
                        "disks": [{"mount": "/", "total": 100 * GB, "used": 38 * GB, "pct": 38.0},
                                  {"mount": "/data", "total": 2000 * GB, "used": int(disk * 20 * GB), "pct": disk}]},
            "listening": [22, 443, 5432] if i == 0 else [22, 443], "subnets": ["10.20.0.0/24"],
            "connections": [{"src": f"10.20.0.{random.randint(100, 105)}", "port": 443, "count": random.randint(3, 30), "open": True}],
            "auth": []}
        if i == 0:
            payload["devices"] = DEVICES if n else DEVICES[:-1]   # son cihaz sonradan "yeni cihaz" olarak görünür
            if n == 1:
                payload["connections"] += [{"src": "203.0.113.50", "port": p, "count": 1, "open": p in (22, 443)}
                                           for p in (21, 22, 23, 25, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5900, 8080, 8443)]
            payload["auth"] = [{"src": "198.51.100.23", "user": u, "result": "fail", "count": random.randint(1, 4)}
                               for u in ("root", "admin", "oracle", "test")]
        send(payload)
    print(f"tur {n + 1}/{rounds} gönderildi")
    if n < rounds - 1:
        time.sleep(2)

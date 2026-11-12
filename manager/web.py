"""HTTP sunucusu: ajan rapor uç noktası, panel API'si ve statik arayüz."""
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .db import DEFAULTS, NUMERIC, check_password, hash_password, sha256

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SESSION_TTL = 7 * 86400
MAX_BODY = 4 * 1024 * 1024
COOKIE = "nobet_session"
CODE_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{1,23}$")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
ROLES = ("admin", "operator", "viewer")   # yönetici, operatör, izleyici
# Kullanıcı yokken de aynı süre harcansın diye doğrulanan sahte özet (kullanıcı adı sızdırmamak için).
DUMMY_HASH = hash_password("nobet-dummy")


INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
                  "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128")]


def is_internal(ip):
    """Kaynak adres yerel/özel ağdan mı? (ipaddress.is_private belgeleme aralıklarını da sayar.)"""
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in INTERNAL_NETS if net.version == addr.version)


class HttpError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


class App:
    def __init__(self, db, engine, notifier):
        self.db, self.engine, self.notifier = db, engine, notifier
        self._fails = {}
        self._fails_lock = threading.Lock()

    # ------------------------------------------------------------------ oturum
    def login(self, username, password, client):
        now = time.time()
        with self._fails_lock:
            recent = [t for t in self._fails.get(client, []) if t > now - 60]
            if len(recent) >= 5:
                raise HttpError(429, "Çok fazla hatalı deneme. Bir dakika sonra tekrar deneyin.")
            user = self.db.one("SELECT * FROM users WHERE username=? AND active=1", (username.strip().lower(),))
            if not check_password(password, user["password_hash"] if user else DUMMY_HASH) or not user:
                self._fails[client] = recent + [now]
                raise HttpError(401, "Kullanıcı adı veya parola hatalı.")
            self._fails.pop(client, None)
        token = secrets.token_urlsafe(32)
        with self.db.tx() as c:
            c.execute("INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
                      (sha256(token), user["id"], now, now + SESSION_TTL))
            c.execute("UPDATE users SET last_login=? WHERE id=?", (now, user["id"]))
        return token

    def session_user(self, token):
        """Geçerli oturumun kullanıcısı; `companies` None ise tüm şirketlere erişir."""
        if not token:
            return None
        user = self.db.one(
            "SELECT u.id, u.username, u.role, u.all_companies FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires_at>? AND u.active=1", (sha256(token), time.time()))
        if user:
            everything = user["role"] == "admin" or user["all_companies"]
            user["companies"] = None if everything else set(self.db.user_company_ids(user["id"]))
        return user

    @staticmethod
    def can_access(user, company_id):
        return user["companies"] is None or company_id in user["companies"]

    # ------------------------------------------------------------------ kullanıcı yönetimi
    def users(self):
        rows = self.db.q("SELECT id, username, role, all_companies, active, created_at, last_login "
                         "FROM users ORDER BY username")
        for r in rows:
            r["companies"] = self.db.user_company_ids(r["id"])
        return rows

    def _company_ids(self, body):
        """İstekteki şirket seçimini doğrular; None = tüm şirketler."""
        if body.get("all_companies"):
            return None
        known = {c["id"] for c in self.db.q("SELECT id FROM companies")}
        try:
            ids = {int(x) for x in (body.get("companies") or [])}
        except (TypeError, ValueError):
            raise HttpError(400, "Geçersiz şirket seçimi.")
        if not ids <= known:
            raise HttpError(400, "Bilinmeyen şirket.")
        return sorted(ids)

    @staticmethod
    def _check_password_rule(password):
        if len(password) < 8:
            raise HttpError(400, "Parola en az 8 karakter olmalı.")

    def create_user(self, body):
        username = str(body.get("username", "")).strip().lower()
        role, password = body.get("role"), str(body.get("password", ""))
        if not USER_RE.match(username):
            raise HttpError(400, "Kullanıcı adı 3-32 karakter olmalı; küçük harf, rakam, nokta, - ve _ kullanılabilir.")
        if role not in ROLES:
            raise HttpError(400, "Geçersiz rol.")
        self._check_password_rule(password)
        if self.db.one("SELECT 1 FROM users WHERE username=?", (username,)):
            raise HttpError(409, "Bu kullanıcı adı zaten var.")
        company_ids = None if role == "admin" else self._company_ids(body)
        return {"id": self.db.create_user(username, password, role, company_ids)}

    def update_user(self, user_id, body, actor):
        target = self.db.one("SELECT * FROM users WHERE id=?", (user_id,))
        if not target:
            raise HttpError(404, "Kullanıcı bulunamadı.")
        role = body.get("role", target["role"])
        active = (1 if body["active"] else 0) if "active" in body else target["active"]
        if role not in ROLES:
            raise HttpError(400, "Geçersiz rol.")
        self._guard_last_admin(target, role, active)
        if target["id"] == actor["id"] and not active:
            raise HttpError(400, "Kendi hesabınızı devre dışı bırakamazsınız.")
        if "password" in body and body["password"] != "":
            self._check_password_rule(str(body["password"]))
            self.db.write("UPDATE users SET password_hash=? WHERE id=?", (hash_password(str(body["password"])), user_id))
            self.db.write("DELETE FROM sessions WHERE user_id=?", (user_id,))
        self.db.write("UPDATE users SET role=?, active=? WHERE id=?", (role, active, user_id))
        if role == "admin":
            self.db.set_user_companies(user_id, None)
        elif "companies" in body or "all_companies" in body or target["role"] == "admin":
            self.db.set_user_companies(user_id, self._company_ids(body))
        if not active:
            self.db.write("DELETE FROM sessions WHERE user_id=?", (user_id,))
        return {"ok": True}

    def delete_user(self, user_id, actor):
        target = self.db.one("SELECT * FROM users WHERE id=?", (user_id,))
        if not target:
            raise HttpError(404, "Kullanıcı bulunamadı.")
        if target["id"] == actor["id"]:
            raise HttpError(400, "Kendi hesabınızı silemezsiniz.")
        self._guard_last_admin(target, "viewer", 0)
        with self.db.tx() as c:
            c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            c.execute("DELETE FROM user_companies WHERE user_id=?", (user_id,))
            c.execute("DELETE FROM users WHERE id=?", (user_id,))
        return {"ok": True}

    def _guard_last_admin(self, target, new_role, new_active):
        """Sistemde her zaman en az bir etkin yönetici kalmalı."""
        if target["role"] == "admin" and target["active"] and (new_role != "admin" or not new_active):
            others = self.db.one("SELECT COUNT(*) n FROM users WHERE role='admin' AND active=1 AND id<>?",
                                 (target["id"],))["n"]
            if not others:
                raise HttpError(400, "Son etkin yönetici hesabı değiştirilemez.")

    def change_own_password(self, user, body, keep_token):
        row = self.db.one("SELECT password_hash FROM users WHERE id=?", (user["id"],))
        if not check_password(str(body.get("current", "")), row["password_hash"]):
            raise HttpError(400, "Mevcut parola hatalı.")
        self._check_password_rule(str(body.get("password", "")))
        self.db.write("UPDATE users SET password_hash=? WHERE id=?", (hash_password(str(body["password"])), user["id"]))
        # Diğer cihazlardaki oturumlar kapanır, bu oturum açık kalır.
        self.db.write("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user["id"], sha256(keep_token)))
        return {"ok": True}

    # ------------------------------------------------------------------ sorgular
    def _scope(self, user, query, column="company_id"):
        """Şirket filtresi: istenen şirket ile kullanıcının yetkili olduğu şirketlerin kesişimi."""
        allowed = user["companies"]
        company = query.get("company")
        if company and company.isdigit():
            if allowed is not None and int(company) not in allowed:
                return " AND 0", []
            return f" AND {column}=?", [int(company)]
        if allowed is None:
            return "", []
        if not allowed:
            return " AND 0", []
        return f" AND {column} IN ({','.join('?' * len(allowed))})", sorted(allowed)

    def _online_after(self):
        return time.time() - self.db.num("offline_seconds")

    def hosts(self, user, query):
        clause, args = self._scope(user, query, "h.company_id")
        rows = self.db.q(
            "SELECT h.*, c.code company_code, c.name company_name, "
            "(SELECT COUNT(*) FROM alerts a WHERE a.host_id=h.id AND a.resolved_at IS NULL AND a.severity='crit') crit, "
            "(SELECT COUNT(*) FROM alerts a WHERE a.host_id=h.id AND a.resolved_at IS NULL AND a.severity='warn') warn "
            "FROM hosts h JOIN companies c ON c.id=h.company_id WHERE 1=1" + clause +
            " ORDER BY c.code, h.hostname", args)
        limit = self._online_after()
        for r in rows:
            r["online"] = bool(r["last_seen"] and r["last_seen"] >= limit)
            for key in ("disks", "listening", "subnets"):
                r[key] = json.loads(r[key] or "[]")
            r["status"] = "down" if not r["online"] else "crit" if r["crit"] else "warn" if r["warn"] else "ok"
        return rows

    def alerts(self, user, query, limit=200):
        clause, args = self._scope(user, query, "a.company_id")
        if query.get("state") == "resolved":
            clause += " AND a.resolved_at IS NOT NULL"
            order = "a.resolved_at DESC"
        else:
            clause += " AND a.resolved_at IS NULL"
            order = "CASE a.severity WHEN 'crit' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END, a.started_at DESC"
        if query.get("host", "").isdigit():
            clause += " AND a.host_id=?"
            args.append(int(query["host"]))
        return self.db.q(
            "SELECT a.*, c.code company_code, c.name company_name, h.hostname FROM alerts a "
            "JOIN companies c ON c.id=a.company_id LEFT JOIN hosts h ON h.id=a.host_id "
            f"WHERE 1=1{clause} ORDER BY {order} LIMIT {int(limit)}", args)

    def devices(self, user, query):
        clause, args = self._scope(user, query, "d.company_id")
        rows = self.db.q(
            "SELECT d.*, c.code company_code, h.hostname seen_by, h.last_scan, h.last_seen host_seen "
            "FROM devices d JOIN companies c ON c.id=d.company_id JOIN hosts h ON h.id=d.host_id "
            "WHERE 1=1" + clause, args)
        limit = self._online_after()
        for r in rows:
            host_online = bool(r["host_seen"] and r["host_seen"] >= limit)
            r["online"] = host_online and r["last_seen"] >= (r["last_scan"] or 0) - 5
            r["unknown"] = not host_online  # ajan çevrimdışıysa cihaz durumu bilinemez
        rows.sort(key=lambda r: (r["company_code"], ipaddress.ip_address(r["ip"]).packed))
        return rows

    def traffic(self, user, query, host_id=None, hours=24, bucket=600):
        clause, args = self._scope(user, query, "h.company_id")
        if host_id:
            clause += " AND h.id=?"
            args.append(host_id)
        since = time.time() - hours * 3600
        return self.db.q(
            "SELECT b*? t, SUM(rx) rx, SUM(tx) tx, AVG(cpu) cpu, AVG(mem) mem FROM ("
            " SELECT CAST(m.ts/? AS INTEGER) b, AVG(m.rx_bps) rx, AVG(m.tx_bps) tx, AVG(m.cpu) cpu, AVG(m.mem_pct) mem"
            " FROM metrics m JOIN hosts h ON h.id=m.host_id WHERE m.ts>=?" + clause +
            " GROUP BY m.host_id, b) GROUP BY b ORDER BY b", [bucket, bucket, since] + args)

    def overview(self, user, query):
        hosts = self.hosts(user, query)
        devices = self.devices(user, query)
        open_alerts = self.alerts(user, query, limit=1000)
        clause, args = self._scope(user, query)
        conn = self.db.one(
            "SELECT COALESCE(SUM(count),0) attempts, COALESCE(SUM(CASE WHEN open=0 THEN count END),0) closed "
            "FROM conn_events WHERE kind='tcp' AND ts>=?" + clause, [time.time() - 86400] + args)
        companies = []
        for c in self.companies(user):
            c = {k: c[k] for k in ("id", "code", "name")}
            own = [h for h in hosts if h["company_id"] == c["id"]]
            if query.get("company") and str(c["id"]) != query["company"]:
                continue
            companies.append({
                **c, "hosts_total": len(own), "hosts_online": sum(h["online"] for h in own),
                "devices": sum(1 for d in devices if d["company_id"] == c["id"]),
                "crit": sum(1 for a in open_alerts if a["company_id"] == c["id"] and a["severity"] == "crit"),
                "warn": sum(1 for a in open_alerts if a["company_id"] == c["id"] and a["severity"] == "warn"),
                "last_seen": max((h["last_seen"] or 0 for h in own), default=0)})
        return {
            "now": time.time(),
            "kpis": {
                "hosts_total": len(hosts), "hosts_online": sum(h["online"] for h in hosts),
                "devices_total": len(devices), "devices_online": sum(1 for d in devices if d["online"]),
                "alerts": {s: sum(1 for a in open_alerts if a["severity"] == s) for s in ("crit", "warn", "info")},
                "attempts_24h": conn["attempts"], "closed_24h": conn["closed"]},
            "companies": companies, "traffic": self.traffic(user, query), "checks": self.checks(user, query),
            "alerts": open_alerts[:6], "hosts": hosts}

    def host_detail(self, user, host_id):
        rows = [h for h in self.hosts(user, {}) if h["id"] == host_id]   # yetkisiz şirket -> 404
        if not rows:
            raise HttpError(404, "Sunucu bulunamadı.")
        host = rows[0]
        events = self.db.q(
            "SELECT * FROM alerts WHERE host_id=? ORDER BY started_at DESC LIMIT 12", (host_id,))
        return {"now": time.time(), "host": host, "series": self.traffic(user, {}, host_id=host_id),
                "alerts": events}

    def connections(self, user, query):
        try:
            hours = max(1, min(720, int(query.get("hours", "24"))))
        except ValueError:
            hours = 24
        now = time.time()
        since = now - hours * 3600
        clause, args = self._scope(user, query, "e.company_id")
        if query.get("host", "").isdigit():
            clause += " AND e.host_id=?"
            args.append(int(query["host"]))
        where = "FROM conn_events e WHERE e.ts>=?" + clause
        args = [since] + args
        tcp = "CASE WHEN e.kind='tcp' THEN e.count ELSE 0 END"
        closed = "CASE WHEN e.kind='tcp' AND e.open=0 THEN e.count ELSE 0 END"
        fail = "CASE WHEN e.kind='ssh_fail' THEN e.count ELSE 0 END"
        ok = "CASE WHEN e.kind='ssh_ok' THEN e.count ELSE 0 END"
        totals = self.db.one(
            f"SELECT COALESCE(SUM({tcp}),0) attempts, COALESCE(SUM({closed}),0) closed, "
            f"COUNT(DISTINCT e.src) sources, COALESCE(SUM({fail}),0) ssh_fail, COALESCE(SUM({ok}),0) ssh_ok {where}",
            args)
        sources = self.db.q(
            f"SELECT e.src, SUM({tcp}) attempts, COUNT(DISTINCT CASE WHEN e.kind='tcp' THEN e.port END) ports, "
            f"SUM({closed}) closed, SUM({fail}) ssh_fail, SUM({ok}) ssh_ok, MAX(e.ts) last {where} "
            f"GROUP BY e.src ORDER BY SUM({tcp})+SUM({fail}) DESC LIMIT 25", args)
        for s in sources:
            s["internal"] = is_internal(s["src"])
        ports = self.db.q(
            f"SELECT e.port, SUM(e.count) attempts, COUNT(DISTINCT e.src) sources, MAX(e.open) open {where} "
            "AND e.kind='tcp' GROUP BY e.port ORDER BY attempts DESC LIMIT 15", args)
        users = self.db.q(
            f"SELECT e.user, SUM(e.count) attempts, COUNT(DISTINCT e.src) sources {where} "
            "AND e.kind='ssh_fail' AND e.user<>'' GROUP BY e.user ORDER BY attempts DESC LIMIT 10", args)
        buckets, size = 48, hours * 3600 / 48
        timeline = [{"t": since + i * size, "open": 0, "closed": 0, "ssh_fail": 0} for i in range(buckets)]
        for r in self.db.q(
                f"SELECT CAST((e.ts-?)/? AS INTEGER) b, SUM({tcp})-SUM({closed}) open, SUM({closed}) closed, "
                f"SUM({fail}) ssh_fail {where} GROUP BY b", [since, size] + args):
            if 0 <= r["b"] < buckets:
                timeline[r["b"]].update(open=r["open"], closed=r["closed"], ssh_fail=r["ssh_fail"])
        recent = self.db.q(
            "SELECT e.ts, e.kind, e.src, e.port, e.user, e.open, e.count, h.hostname, c.code company_code "
            f"FROM conn_events e JOIN hosts h ON h.id=e.host_id JOIN companies c ON c.id=e.company_id "
            f"WHERE e.ts>=?{clause} ORDER BY e.ts DESC, e.id DESC LIMIT 50", args)
        return {"now": now, "hours": hours, "totals": totals, "sources": sources, "ports": ports,
                "users": users, "timeline": timeline, "recent": recent}

    # ------------------------------------------------------------------ servis kontrolleri
    def checks(self, user, query):
        clause, args = self._scope(user, query, "k.company_id")
        rows = self.db.q(
            "SELECT k.*, h.hostname, h.last_seen host_seen, c.code company_code FROM checks k "
            "JOIN hosts h ON h.id=k.host_id JOIN companies c ON c.id=k.company_id WHERE 1=1" + clause +
            " ORDER BY c.code, k.name", args)
        now, limit = time.time(), self._online_after()
        for r in rows:
            stale = not (r["host_seen"] and r["host_seen"] >= limit)
            # Kapalı kontrol ya da çevrimdışı ajan: son bilinen durum güncel sayılmaz.
            r["state"] = "off" if not r["enabled"] else "unknown" if stale or not r["checked_at"] else r["status"]
            up = self.db.one("SELECT AVG(ok) up, COUNT(*) n FROM check_results WHERE check_id=? AND ts>=?",
                             (r["id"], now - 86400))
            r["uptime_24h"] = round(up["up"] * 100, 2) if up["n"] else None
            r["history"] = list(reversed(self.db.q(
                "SELECT ts, ok, latency_ms FROM check_results WHERE check_id=? ORDER BY ts DESC LIMIT 40", (r["id"],))))
        return rows

    @staticmethod
    def _check_fields(body, current=None):
        """Kontrol tanımını doğrular. Ajanlar bu hedeflere bağlanacağı için biçim sıkı tutulur."""
        cur = current or {}
        kind = body.get("type", cur.get("type"))
        name = str(body.get("name", cur.get("name", ""))).strip()[:80]
        target = str(body.get("target", cur.get("target", ""))).strip()
        if kind not in ("tcp", "http"):
            raise HttpError(400, "Tür tcp veya http olmalı.")
        if not name:
            raise HttpError(400, "Kontrol adı gerekli.")
        if len(target) > 300 or any(ch.isspace() or not ch.isprintable() for ch in target):
            raise HttpError(400, "Geçersiz hedef.")
        if kind == "tcp":
            host, _, port = target.rpartition(":")
            if not HOSTNAME_RE.match(host) or not port.isdigit() or not 1 <= int(port) <= 65535:
                raise HttpError(400, "TCP hedefi sunucu:port biçiminde olmalı (ör. 10.0.0.5:5432).")
        else:
            url = urlparse(target)
            if url.scheme not in ("http", "https") or not url.hostname or not HOSTNAME_RE.match(url.hostname):
                raise HttpError(400, "HTTP hedefi http:// veya https:// ile başlayan bir adres olmalı.")
            if url.username or url.password:
                raise HttpError(400, "Adrese kullanıcı adı veya parola yazmayın.")

        def number(key, lo, hi):
            value = body.get(key, cur.get(key))
            if value in (None, ""):
                return None
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise HttpError(400, f"{key} sayı olmalı.")
            if not lo <= value <= hi:
                raise HttpError(400, f"{key} {lo}-{hi} aralığında olmalı.")
            return value
        return {"name": name, "type": kind, "target": target,
                "expect_status": number("expect_status", 100, 599) if kind == "http" else None,
                "slow_ms": number("slow_ms", 1, 600000),
                "verify": 1 if body.get("verify", cur.get("verify", 1)) else 0,
                "enabled": 1 if body.get("enabled", cur.get("enabled", 1)) else 0}

    def create_check(self, body, host):
        f = self._check_fields(body)
        if self.db.one("SELECT COUNT(*) n FROM checks WHERE host_id=?", (host["id"],))["n"] >= 50:
            raise HttpError(400, "Bir sunucuya en fazla 50 kontrol atanabilir.")
        cur = self.db.write(
            "INSERT INTO checks(company_id,host_id,name,type,target,expect_status,slow_ms,verify,enabled,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (host["company_id"], host["id"], f["name"], f["type"], f["target"], f["expect_status"], f["slow_ms"],
             f["verify"], f["enabled"], time.time()))
        return {"id": cur.lastrowid}

    def update_check(self, check_id, body):
        current = self.db.one("SELECT * FROM checks WHERE id=?", (check_id,))
        f = self._check_fields(body, current)
        if f["type"] != current["type"]:
            raise HttpError(400, "Kontrol türü değiştirilemez; yeni bir kontrol ekleyin.")
        if not f["enabled"] or f["target"] != current["target"]:
            self.engine.retire_check(check_id)
        reset = ", status='unknown', fails=0, checked_at=NULL, cert_days=NULL, detail=''" \
            if f["target"] != current["target"] else ""
        self.db.write(f"UPDATE checks SET name=?, target=?, expect_status=?, slow_ms=?, verify=?, enabled=?{reset} "
                      "WHERE id=?", (f["name"], f["target"], f["expect_status"], f["slow_ms"], f["verify"],
                                     f["enabled"], check_id))
        return {"ok": True}

    def delete_check(self, check_id):
        self.engine.retire_check(check_id)
        with self.db.tx() as c:
            c.execute("DELETE FROM check_results WHERE check_id=?", (check_id,))
            c.execute("DELETE FROM checks WHERE id=?", (check_id,))
        return {"ok": True}

    def companies(self, user):
        rows = self.db.q(
            "SELECT c.id, c.code, c.name, c.token_hint, c.telegram_chat_id, c.created_at, "
            "(SELECT COUNT(*) FROM hosts h WHERE h.company_id=c.id) hosts FROM companies c ORDER BY c.code")
        rows = [r for r in rows if self.can_access(user, r["id"])]
        if user["role"] != "admin":   # anahtar ipucu ve bildirim ayarları yalnızca yöneticiye
            rows = [{k: r[k] for k in ("id", "code", "name", "hosts")} for r in rows]
        return rows

    def create_company(self, body):
        code = str(body.get("code", "")).strip().upper()
        name = str(body.get("name", "")).strip()[:120]
        if not CODE_RE.match(code):
            raise HttpError(400, "Kod 2-24 karakter olmalı; yalnızca harf, rakam, - ve _ kullanılabilir.")
        if not name:
            raise HttpError(400, "Şirket adı gerekli.")
        if self.db.one("SELECT 1 FROM companies WHERE code=?", (code,)):
            raise HttpError(409, "Bu kod zaten kullanılıyor.")
        company_id, token = self.db.create_company(code, name)
        return {"id": company_id, "code": code, "name": name, "token": token}

    def settings_view(self):
        cfg = self.db.settings()
        out = {k: cfg[k] for k in DEFAULTS if k != "telegram_bot_token"}
        token = cfg["telegram_bot_token"]
        out["telegram_bot_token_set"] = bool(token)
        out["telegram_bot_token_hint"] = token[-4:] if token else ""
        out["last_notify_error"] = self.notifier.last_error
        return out

    def save_settings(self, body):
        for key, value in body.items():
            if key not in DEFAULTS:
                continue
            value = str(value).strip()[:512]
            if key in NUMERIC:
                try:
                    number = float(value)
                except ValueError:
                    raise HttpError(400, f"{key} sayı olmalı.")
                if number < 0:
                    raise HttpError(400, f"{key} negatif olamaz.")
            if key == "telegram_bot_token" and value == "":
                continue  # boş bırakılırsa mevcut token korunur
            if key in ("webhook_url", "panel_url") and value and not value.startswith(("http://", "https://")):
                raise HttpError(400, f"{key} http:// veya https:// ile başlamalı.")
            self.db.set(key, value)
        return self.settings_view()


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Nobet"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # sessiz; hatalar aşağıda ayrıca yazılır
            pass

        # --- yardımcılar ---
        def _send(self, status, body, content_type="application/json; charset=utf-8", headers=()):
            data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
            if content_type.startswith("application/json"):
                self.send_header("Cache-Control", "no-store")
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                raise HttpError(411, "Content-Length gerekli.")
            if length > MAX_BODY:
                raise HttpError(413, "İstek çok büyük.")
            if "application/json" not in self.headers.get("Content-Type", ""):
                raise HttpError(415, "Content-Type application/json olmalı.")
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                raise HttpError(400, "Geçersiz JSON.")
            if not isinstance(data, dict):
                raise HttpError(400, "JSON nesnesi bekleniyor.")
            return data

        def _session_token(self):
            for part in self.headers.get("Cookie", "").split(";"):
                name, _, value = part.strip().partition("=")
                if name == COOKIE:
                    return value
            return ""

        def _cookie(self, token, max_age):
            secure = "; Secure" if (self.server.is_tls or
                                    self.headers.get("X-Forwarded-Proto") == "https") else ""
            return ("Set-Cookie", f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}")

        def _require_session(self):
            user = app.session_user(self._session_token())
            if not user:
                raise HttpError(401, "Oturum gerekli.")
            return user

        def _static(self, path):
            name = "index.html" if path == "/" else os.path.basename(path)
            full = os.path.join(STATIC_DIR, name)
            if not (path == "/" or path.startswith("/static/")) or not os.path.isfile(full):
                raise HttpError(404, "Bulunamadı.")
            with open(full, "rb") as f:
                ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
                if ctype.startswith("text/") or ctype.endswith("javascript"):
                    ctype += "; charset=utf-8"
                self._send(200, f.read(), ctype, [("Cache-Control", "no-cache")])

        def _dispatch(self, method):
            url = urlparse(self.path)
            path = url.path
            query = {k: v[0] for k, v in parse_qs(url.query).items()}
            try:
                if not path.startswith("/api/"):
                    if method != "GET":
                        raise HttpError(405, "Desteklenmeyen yöntem.")
                    return self._static(path)
                self._api(method, path, query)
            except HttpError as err:
                self._send(err.status, {"error": err.message})
            except ValueError as err:
                self._send(400, {"error": str(err)})
            except Exception as err:  # beklenmeyen hata: ayrıntıyı istemciye sızdırma
                print("sunucu hatası:", method, path, repr(err), flush=True)
                self._send(500, {"error": "Sunucu hatası."})

        def _api(self, method, path, query):
            # --- kimlik doğrulaması farklı olan uç noktalar ---
            if (method, path) == ("POST", "/api/agent/report"):
                auth = self.headers.get("Authorization", "")
                company = app.db.company_by_token(auth[7:]) if auth.startswith("Bearer ") else None
                if not company:
                    raise HttpError(401, "Geçersiz ajan anahtarı.")
                host_id = app.engine.ingest(company, self._body())
                return self._send(200, {"ok": True, "company": company["code"],
                                        "checks": app.engine.agent_checks(company["id"], host_id)})
            if (method, path) == ("POST", "/api/login"):
                body = self._body()
                token = app.login(str(body.get("username", "")), str(body.get("password", "")),
                                  self.client_address[0])
                return self._send(200, {"ok": True}, headers=[self._cookie(token, SESSION_TTL)])
            if (method, path) == ("POST", "/api/logout"):
                token = self._session_token()
                if token:
                    app.db.write("DELETE FROM sessions WHERE token_hash=?", (sha256(token),))
                return self._send(200, {"ok": True}, headers=[self._cookie("", 0)])

            user = self._require_session()
            m = re.fullmatch(r"/api/(\w+)(?:/(\d+))?(?:/(\w+))?", path)
            if not m:
                raise HttpError(404, "Bulunamadı.")
            resource, rid, action = m.group(1), int(m.group(2)) if m.group(2) else None, m.group(3)
            is_admin = user["role"] == "admin"

            def admin_only():
                if not is_admin:
                    raise HttpError(403, "Bu işlem için yönetici yetkisi gerekli.")

            def owned(table, row_id):
                """Kayıt kullanıcının yetkili olduğu bir şirkete ait değilse 404 (varlığını da sızdırma)."""
                row = app.db.one(f"SELECT company_id FROM {table} WHERE id=?", (row_id,))
                if not row or not app.can_access(user, row["company_id"]):
                    raise HttpError(404, "Bulunamadı.")

            if method == "GET":
                if resource == "me":
                    return self._send(200, {"id": user["id"], "username": user["username"], "role": user["role"],
                                            "all_companies": user["companies"] is None,
                                            "companies": sorted(user["companies"] or [])})
                if resource == "overview":
                    return self._send(200, app.overview(user, query))
                if resource == "hosts" and rid:
                    return self._send(200, app.host_detail(user, rid))
                if resource == "hosts":
                    return self._send(200, {"now": time.time(), "hosts": app.hosts(user, query)})
                if resource == "devices":
                    return self._send(200, {"now": time.time(), "devices": app.devices(user, query)})
                if resource == "connections":
                    return self._send(200, app.connections(user, query))
                if resource == "alerts":
                    return self._send(200, {"now": time.time(), "alerts": app.alerts(user, query)})
                if resource == "companies":
                    return self._send(200, {"companies": app.companies(user)})
                if resource == "checks":
                    return self._send(200, {"now": time.time(), "checks": app.checks(user, query)})
                if resource == "settings":
                    admin_only()
                    return self._send(200, app.settings_view())
                if resource == "users":
                    admin_only()
                    return self._send(200, {"users": app.users()})
                raise HttpError(404, "Bulunamadı.")

            if method != "POST":
                raise HttpError(405, "Desteklenmeyen yöntem.")
            body = self._body()
            if resource == "me" and action == "password":
                return self._send(200, app.change_own_password(user, body, self._session_token()))
            if user["role"] == "viewer":
                raise HttpError(403, "İzleyici rolü değişiklik yapamaz.")

            # --- operatör ve yönetici: kendi şirketlerindeki uyarı ve cihazlar ---
            if resource == "alerts" and rid and action == "ack":
                owned("alerts", rid)
                app.db.write("UPDATE alerts SET acked_at=?, acked_by=? WHERE id=? AND acked_at IS NULL",
                             (time.time(), user["username"], rid))
                return self._send(200, {"ok": True})
            if resource == "devices" and rid:
                owned("devices", rid)
                if "watched" in body:
                    app.db.write("UPDATE devices SET watched=? WHERE id=?", (1 if body["watched"] else 0, rid))
                if "label" in body:
                    app.db.write("UPDATE devices SET label=? WHERE id=?", (str(body["label"]).strip()[:80], rid))
                return self._send(200, {"ok": True})

            if resource == "checks" and rid and action == "delete":
                owned("checks", rid)
                return self._send(200, app.delete_check(rid))
            if resource == "checks" and rid:
                owned("checks", rid)
                return self._send(200, app.update_check(rid, body))
            if resource == "checks":
                try:
                    host_id = int(body.get("host_id"))
                except (TypeError, ValueError):
                    raise HttpError(400, "Kontrolü çalıştıracak sunucuyu seçin.")
                owned("hosts", host_id)
                host = app.db.one("SELECT id, company_id FROM hosts WHERE id=?", (host_id,))
                return self._send(201, app.create_check(body, host))

            # --- yalnızca yönetici ---
            admin_only()
            if resource == "users" and rid and action == "delete":
                return self._send(200, app.delete_user(rid, user))
            if resource == "users" and rid:
                return self._send(200, app.update_user(rid, body, user))
            if resource == "users":
                return self._send(201, app.create_user(body))
            if resource == "companies" and rid and action == "token":
                if not app.db.one("SELECT 1 FROM companies WHERE id=?", (rid,)):
                    raise HttpError(404, "Şirket bulunamadı.")
                return self._send(200, {"token": app.db.rotate_token(rid)})
            if resource == "companies" and rid:
                if "telegram_chat_id" in body:
                    app.db.write("UPDATE companies SET telegram_chat_id=? WHERE id=?",
                                 (str(body["telegram_chat_id"]).strip()[:64], rid))
                if str(body.get("name", "")).strip():
                    app.db.write("UPDATE companies SET name=? WHERE id=?", (str(body["name"]).strip()[:120], rid))
                return self._send(200, {"ok": True})
            if resource == "companies":
                return self._send(201, app.create_company(body))
            if resource == "settings" and action == "test":
                try:
                    sent = app.notifier.deliver({
                        "chat_id": str(body.get("chat_id", "")),
                        "text": "<b>Nöbet</b> test bildirimi: bağlantı çalışıyor."})
                except Exception as err:
                    raise HttpError(502, f"Gönderilemedi: {err}")
                if not sent:
                    raise HttpError(400, "Yapılandırılmış bildirim kanalı yok.")
                return self._send(200, {"ok": True, "sent": sent})
            if resource == "settings":
                return self._send(200, app.save_settings(body))
            raise HttpError(404, "Bulunamadı.")

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

    return Handler


def make_server(app, host, port, cert=None, key=None):
    server = ThreadingHTTPServer((host, port), make_handler(app))
    server.daemon_threads = True
    server.is_tls = False
    if cert:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        server.is_tls = True
    return server

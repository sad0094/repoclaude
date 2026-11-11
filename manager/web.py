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

from .db import DEFAULTS, NUMERIC, check_password, sha256

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SESSION_TTL = 7 * 86400
MAX_BODY = 4 * 1024 * 1024
COOKIE = "nobet_session"
CODE_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{1,23}$")


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
    def login(self, password, client):
        now = time.time()
        with self._fails_lock:
            recent = [t for t in self._fails.get(client, []) if t > now - 60]
            if len(recent) >= 5:
                raise HttpError(429, "Çok fazla hatalı deneme. Bir dakika sonra tekrar deneyin.")
            if not check_password(password, self.db.get("admin_hash")):
                self._fails[client] = recent + [now]
                raise HttpError(401, "Parola hatalı.")
            self._fails.pop(client, None)
        token = secrets.token_urlsafe(32)
        self.db.write("INSERT INTO sessions(token_hash,created_at,expires_at) VALUES(?,?,?)",
                      (sha256(token), now, now + SESSION_TTL))
        return token

    def session_valid(self, token):
        if not token:
            return False
        return self.db.one("SELECT 1 FROM sessions WHERE token_hash=? AND expires_at>?",
                           (sha256(token), time.time())) is not None

    # ------------------------------------------------------------------ sorgular
    def _scope(self, query, column="company_id"):
        company = query.get("company")
        if company and company.isdigit():
            return f" AND {column}=?", [int(company)]
        return "", []

    def _online_after(self):
        return time.time() - self.db.num("offline_seconds")

    def hosts(self, query):
        clause, args = self._scope(query, "h.company_id")
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

    def alerts(self, query, limit=200):
        clause, args = self._scope(query, "a.company_id")
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

    def devices(self, query):
        clause, args = self._scope(query, "d.company_id")
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

    def traffic(self, query, host_id=None, hours=24, bucket=600):
        clause, args = self._scope(query, "h.company_id")
        if host_id:
            clause += " AND h.id=?"
            args.append(host_id)
        since = time.time() - hours * 3600
        return self.db.q(
            "SELECT b*? t, SUM(rx) rx, SUM(tx) tx, AVG(cpu) cpu, AVG(mem) mem FROM ("
            " SELECT CAST(m.ts/? AS INTEGER) b, AVG(m.rx_bps) rx, AVG(m.tx_bps) tx, AVG(m.cpu) cpu, AVG(m.mem_pct) mem"
            " FROM metrics m JOIN hosts h ON h.id=m.host_id WHERE m.ts>=?" + clause +
            " GROUP BY m.host_id, b) GROUP BY b ORDER BY b", [bucket, bucket, since] + args)

    def overview(self, query):
        hosts = self.hosts(query)
        devices = self.devices(query)
        open_alerts = self.alerts(query, limit=1000)
        clause, args = self._scope(query)
        conn = self.db.one(
            "SELECT COALESCE(SUM(count),0) attempts, COALESCE(SUM(CASE WHEN open=0 THEN count END),0) closed "
            "FROM conn_events WHERE kind='tcp' AND ts>=?" + clause, [time.time() - 86400] + args)
        companies = []
        for c in self.db.q("SELECT id, code, name FROM companies ORDER BY code"):
            own = [h for h in hosts if h["company_id"] == c["id"]]
            if query.get("company") and not own and str(c["id"]) != query["company"]:
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
            "companies": companies, "traffic": self.traffic(query),
            "alerts": open_alerts[:6], "hosts": hosts}

    def host_detail(self, host_id):
        rows = [h for h in self.hosts({}) if h["id"] == host_id]
        if not rows:
            raise HttpError(404, "Sunucu bulunamadı.")
        host = rows[0]
        events = self.db.q(
            "SELECT * FROM alerts WHERE host_id=? ORDER BY started_at DESC LIMIT 12", (host_id,))
        return {"now": time.time(), "host": host, "series": self.traffic({}, host_id=host_id),
                "alerts": events}

    def connections(self, query):
        try:
            hours = max(1, min(720, int(query.get("hours", "24"))))
        except ValueError:
            hours = 24
        now = time.time()
        since = now - hours * 3600
        clause, args = self._scope(query, "e.company_id")
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

    def companies(self):
        return self.db.q(
            "SELECT c.id, c.code, c.name, c.token_hint, c.telegram_chat_id, c.created_at, "
            "(SELECT COUNT(*) FROM hosts h WHERE h.company_id=c.id) hosts FROM companies c ORDER BY c.code")

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
            if not app.session_valid(self._session_token()):
                raise HttpError(401, "Oturum gerekli.")

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
                app.engine.ingest(company, self._body())
                return self._send(200, {"ok": True, "company": company["code"]})
            if (method, path) == ("POST", "/api/login"):
                token = app.login(str(self._body().get("password", "")), self.client_address[0])
                return self._send(200, {"ok": True}, headers=[self._cookie(token, SESSION_TTL)])
            if (method, path) == ("POST", "/api/logout"):
                token = self._session_token()
                if token:
                    app.db.write("DELETE FROM sessions WHERE token_hash=?", (sha256(token),))
                return self._send(200, {"ok": True}, headers=[self._cookie("", 0)])

            self._require_session()
            m = re.fullmatch(r"/api/(\w+)(?:/(\d+))?(?:/(\w+))?", path)
            if not m:
                raise HttpError(404, "Bulunamadı.")
            resource, rid, action = m.group(1), int(m.group(2)) if m.group(2) else None, m.group(3)

            if method == "GET":
                if resource == "me":
                    return self._send(200, {"ok": True})
                if resource == "overview":
                    return self._send(200, app.overview(query))
                if resource == "hosts" and rid:
                    return self._send(200, app.host_detail(rid))
                if resource == "hosts":
                    return self._send(200, {"now": time.time(), "hosts": app.hosts(query)})
                if resource == "devices":
                    return self._send(200, {"now": time.time(), "devices": app.devices(query)})
                if resource == "connections":
                    return self._send(200, app.connections(query))
                if resource == "alerts":
                    return self._send(200, {"now": time.time(), "alerts": app.alerts(query)})
                if resource == "companies":
                    return self._send(200, {"companies": app.companies()})
                if resource == "settings":
                    return self._send(200, app.settings_view())
                raise HttpError(404, "Bulunamadı.")

            if method != "POST":
                raise HttpError(405, "Desteklenmeyen yöntem.")
            body = self._body()
            if resource == "alerts" and rid and action == "ack":
                app.db.write("UPDATE alerts SET acked_at=? WHERE id=? AND acked_at IS NULL", (time.time(), rid))
                return self._send(200, {"ok": True})
            if resource == "devices" and rid:
                if "watched" in body:
                    app.db.write("UPDATE devices SET watched=? WHERE id=?", (1 if body["watched"] else 0, rid))
                if "label" in body:
                    app.db.write("UPDATE devices SET label=? WHERE id=?", (str(body["label"]).strip()[:80], rid))
                return self._send(200, {"ok": True})
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

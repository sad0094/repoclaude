"""Uçtan uca ve birim testleri: python3 -m unittest discover -s tests -v"""
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "agent"))

import nobet_agent as agent  # noqa: E402
from manager import notify  # noqa: E402
from manager.__main__ import build  # noqa: E402
from manager.db import hash_password  # noqa: E402
from manager.web import make_server  # noqa: E402


class FakeTelegram(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeTelegram.received.append((self.path, body))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


def report(hostname="srv-1", disk=40.0, **extra):
    base = {
        "agent_version": "test", "capture_mode": "sniffer",
        "host": {"id": hostname, "hostname": hostname, "os": "TestOS", "ip": "10.0.0.5", "uptime_s": 100, "cores": 4},
        "metrics": {"cpu": 10, "mem_pct": 30, "mem_used": 3, "mem_total": 10, "load1": 0.1, "rx_bps": 1000,
                    "tx_bps": 500, "disks": [{"mount": "/", "total": 100, "used": disk, "pct": disk}]},
        "listening": [22, 443], "subnets": ["10.0.0.0/24"], "connections": [], "auth": []}
    base.update(extra)
    return base


class ManagerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db, self.notifier, self.engine, self.app = build(os.path.join(self.tmp.name, "t.db"))
        self.db.create_user("admin", "gizli-parola", "admin")
        FakeTelegram.received = []
        self.tg = HTTPServer(("127.0.0.1", 0), FakeTelegram)
        threading.Thread(target=self.tg.serve_forever, daemon=True).start()
        notify.TELEGRAM_API = f"http://127.0.0.1:{self.tg.server_port}"
        self.db.set("telegram_bot_token", "123:ABC")
        self.db.set("telegram_chat_id", "-100default")
        self.notifier.start()
        self.server = make_server(self.app, "127.0.0.1", 0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.cookie = ""
        self.cookie = self.login("admin", "gizli-parola")
        self.xxxx = self.call("/api/companies", {"code": "xxxx", "name": "XXXX LTD Şirketi"})
        self.yyy = self.call("/api/companies", {"code": "YYY", "name": "YYY LTD Şirketi"})

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tg.shutdown()
        self.tg.server_close()
        self.tmp.cleanup()

    def login(self, username, password):
        saved, self.cookie = self.cookie, ""
        try:
            resp = self.call("/api/login", {"username": username, "password": password}, raw=True)
            return resp.headers["Set-Cookie"].split(";")[0]
        finally:
            self.cookie = saved

    def as_user(self, username, password="parola-12345"):
        """Sonraki çağrıları bu kullanıcının oturumuyla yapar."""
        self.cookie = self.login(username, password)

    def call(self, path, body=None, token=None, raw=False):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        elif self.cookie:
            headers["Cookie"] = self.cookie
        req = urllib.request.Request(self.base + path, headers=headers,
                                     data=None if body is None else json.dumps(body).encode())
        resp = urllib.request.urlopen(req, timeout=5)
        return resp if raw else json.loads(resp.read())

    def status(self, path, body=None, token=None, cookie=True):
        saved = self.cookie
        if not cookie:
            self.cookie = ""
        try:
            return self.call(path, body, token, raw=True).status
        except urllib.error.HTTPError as err:
            return err.code
        finally:
            self.cookie = saved

    def company(self, c):
        return self.db.one("SELECT * FROM companies WHERE id=?", (c["id"],))

    def messages(self):
        self.notifier.queue.join()
        return [body for _, body in FakeTelegram.received]

    def open_alerts(self):
        return {a["key"]: a for a in self.call("/api/alerts")["alerts"]}

    # ---------------------------------------------------------------- kimlik doğrulama
    def test_auth_is_required(self):
        self.assertEqual(self.status("/api/overview", cookie=False), 401)
        self.assertEqual(self.status("/api/companies", {"code": "ZZ", "name": "z"}, cookie=False), 401)
        self.assertEqual(self.status("/api/agent/report", report(), token="nbt_yanlis"), 401)
        self.assertEqual(self.status("/api/login", {"username": "admin", "password": "yanlis"}, cookie=False), 401)
        self.assertEqual(self.status("/api/login", {"username": "yok", "password": "gizli-parola"}, cookie=False), 401)
        self.assertEqual(self.status("/api/overview"), 200)

    def test_login_is_rate_limited(self):
        for _ in range(5):
            self.assertEqual(self.status("/api/login", {"username": "admin", "password": "x"}, cookie=False), 401)
        self.assertEqual(self.status("/api/login", {"username": "admin", "password": "gizli-parola"}, cookie=False), 429)

    def test_static_cannot_escape_directory(self):
        self.assertEqual(self.status("/static/..%2Fdb.py"), 404)
        self.assertEqual(self.status("/static/../db.py"), 404)
        self.assertEqual(self.status("/static/app.js"), 200)

    # ---------------------------------------------------------------- çok şirketli yapı
    def test_reports_are_separated_per_company(self):
        self.call("/api/agent/report", report("xxxx-srv"), token=self.xxxx["token"])
        self.call("/api/agent/report", report("yyy-srv"), token=self.yyy["token"])
        everything = self.call("/api/hosts")["hosts"]
        self.assertEqual({h["company_code"] for h in everything}, {"XXXX", "YYY"})
        only = self.call(f"/api/hosts?company={self.yyy['id']}")["hosts"]
        self.assertEqual([h["hostname"] for h in only], ["yyy-srv"])
        overview = self.call("/api/overview")
        self.assertEqual(overview["kpis"]["hosts_online"], 2)
        self.assertEqual(len(overview["companies"]), 2)

    def test_rotated_token_invalidates_old_one(self):
        new = self.call(f"/api/companies/{self.xxxx['id']}/token", {})["token"]
        self.assertEqual(self.status("/api/agent/report", report(), token=self.xxxx["token"]), 401)
        self.assertEqual(self.status("/api/agent/report", report(), token=new), 200)

    # ---------------------------------------------------------------- kullanıcılar ve roller
    def make_user(self, username, role, companies=None, all_companies=False):
        body = {"username": username, "password": "parola-12345", "role": role,
                "companies": [c["id"] for c in companies or []], "all_companies": all_companies}
        return self.call("/api/users", body)["id"]

    def seed_two_companies(self):
        scan = [{"src": "203.0.113.9", "port": p, "count": 1, "open": False} for p in range(100, 120)]
        dev = [{"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:01", "hostname": "gw"}]
        self.call("/api/agent/report", report("xxxx-srv", disk=95, connections=scan, devices=dev), token=self.xxxx["token"])
        self.call("/api/agent/report", report("yyy-srv", disk=95, devices=dev), token=self.yyy["token"])

    def test_company_scoped_user_sees_only_assigned_company(self):
        self.seed_two_companies()
        hosts = {h["hostname"]: h["id"] for h in self.call("/api/hosts")["hosts"]}
        self.make_user("xxxx.izleyici", "viewer", [self.xxxx])
        self.as_user("xxxx.izleyici")
        me = self.call("/api/me")
        self.assertEqual((me["role"], me["companies"], me["all_companies"]), ("viewer", [self.xxxx["id"]], False))
        self.assertEqual([c["code"] for c in self.call("/api/companies")["companies"]], ["XXXX"])
        self.assertNotIn("token_hint", self.call("/api/companies")["companies"][0])
        self.assertEqual([h["hostname"] for h in self.call("/api/hosts")["hosts"]], ["xxxx-srv"])
        self.assertEqual({a["company_code"] for a in self.call("/api/alerts")["alerts"]}, {"XXXX"})
        self.assertEqual({d["company_code"] for d in self.call("/api/devices")["devices"]}, {"XXXX"})
        overview = self.call("/api/overview")
        self.assertEqual((overview["kpis"]["hosts_total"], len(overview["companies"])), (1, 1))
        self.assertEqual(self.call("/api/connections?hours=1")["totals"]["attempts"], 20)
        # Başka şirketi açıkça istemek de veri döndürmez.
        other = f"?company={self.yyy['id']}"
        self.assertEqual(self.call("/api/hosts" + other)["hosts"], [])
        self.assertEqual(self.call("/api/alerts" + other)["alerts"], [])
        self.assertEqual(self.call("/api/connections" + other + "&hours=1")["totals"]["attempts"], 0)
        self.assertEqual(self.status(f"/api/hosts/{hosts['yyy-srv']}"), 404)
        self.assertEqual(self.status(f"/api/hosts/{hosts['xxxx-srv']}"), 200)

    def test_viewer_is_read_only_and_operator_is_limited_to_own_company(self):
        self.seed_two_companies()
        alerts = {a["company_code"]: a["id"] for a in self.call("/api/alerts")["alerts"] if a["key"] == "disk:/"}
        devices = {d["company_code"]: d["id"] for d in self.call("/api/devices")["devices"]}
        self.make_user("izleyici", "viewer", all_companies=True)
        self.make_user("yyy.operator", "operator", [self.yyy])

        self.as_user("izleyici")
        self.assertEqual(len(self.call("/api/hosts")["hosts"]), 2)
        self.assertEqual(self.status(f"/api/alerts/{alerts['XXXX']}/ack", {}), 403)
        self.assertEqual(self.status(f"/api/devices/{devices['XXXX']}", {"watched": True}), 403)

        self.as_user("yyy.operator")
        self.assertEqual(self.status(f"/api/alerts/{alerts['XXXX']}/ack", {}), 404)
        self.assertEqual(self.status(f"/api/devices/{devices['XXXX']}", {"watched": True}), 404)
        self.assertEqual(self.status(f"/api/alerts/{alerts['YYY']}/ack", {}), 200)
        self.assertEqual(self.status(f"/api/devices/{devices['YYY']}", {"watched": True}), 200)
        acked = [a for a in self.call("/api/alerts")["alerts"] if a["id"] == alerts["YYY"]][0]
        self.assertEqual(acked["acked_by"], "yyy.operator")
        self.assertIsNone(self.db.one("SELECT acked_at FROM alerts WHERE id=?", (alerts["XXXX"],))["acked_at"])
        # Yönetim uç noktaları operatöre kapalı.
        for path, body in (("/api/settings", None), ("/api/users", None), ("/api/settings", {"disk_crit": "1"}),
                           ("/api/companies", {"code": "ZZ", "name": "z"}), ("/api/settings/test", {}),
                           (f"/api/companies/{self.yyy['id']}/token", {}),
                           ("/api/users", {"username": "yeni", "password": "parola-12345", "role": "admin"})):
            self.assertEqual(self.status(path, body), 403, path)

    def test_user_management_rules(self):
        admin_id = self.call("/api/me")["id"]
        uid = self.make_user("ayse", "operator", [self.xxxx])
        self.assertEqual(self.status("/api/users", {"username": "ayse", "password": "parola-12345", "role": "viewer"}), 409)
        self.assertEqual(self.status("/api/users", {"username": "A B", "password": "parola-12345", "role": "viewer"}), 400)
        self.assertEqual(self.status("/api/users", {"username": "kisa", "password": "123", "role": "viewer"}), 400)
        self.assertEqual(self.status("/api/users", {"username": "rol", "password": "parola-12345", "role": "root"}), 400)
        self.assertEqual(self.status("/api/users", {"username": "sirket", "password": "parola-12345", "role": "viewer",
                                                    "companies": [9999]}), 400)
        # Son yönetici korunur; kendi hesabını silemez.
        self.assertEqual(self.status(f"/api/users/{admin_id}", {"role": "viewer"}), 400)
        self.assertEqual(self.status(f"/api/users/{admin_id}", {"active": False}), 400)
        self.assertEqual(self.status(f"/api/users/{admin_id}/delete", {}), 400)
        # Şirket ataması değişince erişim hemen değişir; devre dışı bırakınca oturum düşer.
        self.call(f"/api/agent/report", report("yyy-srv"), token=self.yyy["token"])
        admin_cookie = self.cookie
        self.as_user("ayse")
        ayse_cookie = self.cookie
        self.assertEqual(self.call("/api/hosts")["hosts"], [])
        self.cookie = admin_cookie
        self.call(f"/api/users/{uid}", {"companies": [self.yyy["id"]]})
        self.cookie = ayse_cookie
        self.assertEqual(len(self.call("/api/hosts")["hosts"]), 1)
        self.cookie = admin_cookie
        self.call(f"/api/users/{uid}", {"active": False})
        self.cookie = ayse_cookie
        self.assertEqual(self.status("/api/hosts"), 401)
        self.cookie = admin_cookie
        self.assertEqual(self.status("/api/login", {"username": "ayse", "password": "parola-12345"}, cookie=False), 401)
        self.call(f"/api/users/{uid}/delete", {})
        self.assertEqual([u["username"] for u in self.call("/api/users")["users"]], ["admin"])

    def test_change_own_password(self):
        self.make_user("mehmet", "viewer", [self.xxxx])
        self.as_user("mehmet")
        self.assertEqual(self.status("/api/me/password", {"current": "yanlis", "password": "yeni-parola-1"}), 400)
        self.assertEqual(self.status("/api/me/password", {"current": "parola-12345", "password": "kisa"}), 400)
        self.call("/api/me/password", {"current": "parola-12345", "password": "yeni-parola-1"})
        self.assertEqual(self.status("/api/me"), 200)   # mevcut oturum açık kalır
        self.assertEqual(self.status("/api/login", {"username": "mehmet", "password": "parola-12345"}, cookie=False), 401)
        self.assertEqual(self.status("/api/login", {"username": "mehmet", "password": "yeni-parola-1"}, cookie=False), 200)

    def test_legacy_single_admin_database_is_migrated(self):
        import sqlite3
        from manager.db import DB
        path = os.path.join(self.tmp.name, "eski.db")
        old = sqlite3.connect(path)
        old.executescript("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);"
                          "CREATE TABLE sessions(token_hash TEXT PRIMARY KEY, created_at REAL, expires_at REAL);")
        old.execute("INSERT INTO settings VALUES('admin_hash', ?)", (hash_password("eski-parola"),))
        old.commit()
        old.close()
        db = DB(path)
        user = db.one("SELECT username, role, password_hash FROM users")
        self.assertEqual((user["username"], user["role"]), ("admin", "admin"))
        from manager.db import check_password
        self.assertTrue(check_password("eski-parola", user["password_hash"]))
        self.assertEqual(db.get("admin_hash"), "")

    # ---------------------------------------------------------------- işlem günlüğü
    def audit(self, **params):
        query = urllib.parse.urlencode(params)
        return self.call("/api/audit" + ("?" + query if query else ""))["entries"]

    def test_audit_log_records_actions_without_secrets(self):
        self.seed_two_companies()
        alert = [a for a in self.call("/api/alerts")["alerts"] if a["key"] == "disk:/" and a["company_code"] == "YYY"][0]
        device = [d for d in self.call("/api/devices")["devices"] if d["company_code"] == "YYY"][0]
        host = [h for h in self.call("/api/hosts")["hosts"] if h["company_code"] == "YYY"][0]
        uid = self.make_user("yyy.operator", "operator", [self.yyy])
        self.call(f"/api/users/{uid}", {"role": "viewer", "companies": [self.xxxx["id"]], "password": "yepyeni-parola-1"})
        self.call(f"/api/users/{uid}", {"role": "operator", "companies": [self.yyy["id"]], "password": "parola-12345"})
        self.call("/api/settings", {"telegram_bot_token": "999:GIZLI", "webhook_url": "https://hooks.example/GIZLI-YOL",
                                    "disk_crit": "95", "disk_warn": "80"})
        self.call(f"/api/companies/{self.yyy['id']}/token", {})
        self.status("/api/login", {"username": "yyy.operator", "password": "yanlis-parola"}, cookie=False)
        admin_cookie = self.cookie
        self.as_user("yyy.operator")
        self.call(f"/api/alerts/{alert['id']}/ack", {})
        self.call(f"/api/alerts/{alert['id']}/ack", {})          # ikinci kez: yeni kayıt oluşmaz
        self.call(f"/api/devices/{device['id']}", {"watched": True, "label": "Ana yönlendirici"})
        cid = self.add_check(host["id"], name="Site", target="http://10.1.0.5/")
        self.call(f"/api/checks/{cid}", {"enabled": False})
        self.call(f"/api/checks/{cid}/delete", {})
        self.assertEqual(self.status("/api/audit"), 403)         # günlük yalnızca yöneticiye açık
        self.cookie = admin_cookie

        entries = self.audit()
        by_action = {}
        for e in entries:
            by_action.setdefault(e["action"], []).append(e)
        for action in ("auth.login", "auth.login_failed", "user.create", "user.update", "settings.update",
                       "company.create", "company.token", "alert.ack", "device.watch", "device.label",
                       "check.create", "check.update", "check.delete"):
            self.assertIn(action, by_action, action)
        self.assertEqual(len(by_action["alert.ack"]), 1)
        ack = by_action["alert.ack"][0]
        self.assertEqual((ack["username"], ack["role"], ack["company_code"], ack["ip"]),
                         ("yyy.operator", "operator", "YYY", "127.0.0.1"))
        self.assertIn("Disk doluluğu", ack["target"])
        self.assertEqual(by_action["auth.login_failed"][0]["username"], "yyy.operator")
        self.assertIn("rol: operator -> viewer", by_action["user.update"][-1]["detail"])
        self.assertIn("şirketler: YYY -> XXXX", by_action["user.update"][-1]["detail"])
        settings = {e["detail"] for e in by_action["settings.update"]}
        self.assertIn("disk_crit: 90 -> 95", settings)
        self.assertEqual(len(settings), 3)                       # değişmeyen disk_warn kaydedilmez
        # Gizli değerler ve parolalar hiçbir kayıtta geçmez.
        dump = json.dumps(entries, ensure_ascii=False)
        for secret in ("GIZLI", "parola-12345", "yepyeni-parola-1", "yanlis-parola", "nbt_"):
            self.assertNotIn(secret, dump)
        # Filtreler ve sayfalama
        self.assertEqual({e["action"].split(".")[0] for e in self.audit(area="check")}, {"check"})
        self.assertTrue(all(e["company_code"] == "YYY" for e in self.audit(company=self.yyy["id"])))
        self.assertEqual({e["action"] for e in self.audit(q="yönlendirici")}, {"device.label"})
        # "%" joker değil, düz karakter olarak aranır: yalnızca içinde % geçen kayıt döner.
        self.assertEqual([e["action"] for e in self.audit(q="%95")], ["alert.ack"])
        self.assertEqual({e["action"] for e in self.audit(q="_")}, {"settings.update"})   # yalnızca adında _ geçenler
        older = self.audit(before=entries[2]["id"])
        self.assertEqual(older[0]["id"], entries[3]["id"])
        # Günlüğü değiştiren veya silen bir uç nokta yok.
        self.assertEqual(self.status("/api/audit", {}), 404)
        self.assertEqual(self.status(f"/api/audit/{entries[0]['id']}/delete", {}), 404)

    # ---------------------------------------------------------------- servis sağlık kontrolleri
    def add_check(self, host_id, **fields):
        body = {"host_id": host_id, "name": "ERP", "type": "http", "target": "https://erp.ic/saglik"}
        body.update(fields)
        return self.call("/api/checks", body)["id"]

    def test_checks_are_delivered_to_agent_and_drive_alerts(self):
        first = self.call("/api/agent/report", report("xxxx-srv"), token=self.xxxx["token"])
        self.assertEqual(first["checks"], [])
        host_id = self.call("/api/hosts")["hosts"][0]["id"]
        cid = self.add_check(host_id, slow_ms=500)
        sent = self.call("/api/agent/report", report("xxxx-srv"), token=self.xxxx["token"])["checks"]
        self.assertEqual(sent, [{"id": cid, "type": "http", "target": "https://erp.ic/saglik",
                                 "expect_status": None, "verify": True, "timeout": 5}])
        check = lambda: self.call("/api/checks")["checks"][0]
        self.assertEqual(check()["state"], "unknown")

        def result(**r):
            self.call("/api/agent/report", report("xxxx-srv", checks=[dict(id=cid, **r)]), token=self.xxxx["token"])
        result(ok=True, latency_ms=40, status_code=200, cert_days=90)
        self.assertEqual((check()["state"], check()["uptime_24h"]), ("ok", 100.0))
        result(ok=True, latency_ms=900, status_code=200, cert_days=90)
        self.assertEqual(check()["state"], "warn")                     # yavaş
        result(ok=False, latency_ms=5000, error="Zaman aşımı")
        self.assertEqual(check()["state"], "crit")
        self.assertNotIn(f"check:{cid}", self.open_alerts())           # tek hata uyarı üretmez
        result(ok=False, latency_ms=5000, error="Zaman aşımı")
        alert = self.open_alerts()[f"check:{cid}"]
        self.assertEqual(alert["severity"], "crit")
        self.assertIn("Zaman aşımı", alert["detail"])
        self.assertIn("Servis yanıt vermiyor: ERP", self.messages()[-1]["text"])
        self.assertEqual(check()["uptime_24h"], 50.0)
        result(ok=True, latency_ms=30, status_code=200, cert_days=10)
        alerts = self.open_alerts()
        self.assertNotIn(f"check:{cid}", alerts)
        self.assertEqual(alerts[f"cert:{cid}"]["severity"], "warn")    # sertifika 10 gün
        result(ok=True, latency_ms=30, status_code=200, cert_days=2)
        self.assertEqual(self.open_alerts()[f"cert:{cid}"]["severity"], "crit")
        self.call(f"/api/checks/{cid}/delete", {})
        self.assertEqual(self.open_alerts(), {})
        self.assertEqual(self.call("/api/checks")["checks"], [])

    def test_check_results_cannot_cross_hosts_or_companies(self):
        self.call("/api/agent/report", report("xxxx-srv"), token=self.xxxx["token"])
        self.call("/api/agent/report", report("yyy-srv"), token=self.yyy["token"])
        hosts = {h["hostname"]: h["id"] for h in self.call("/api/hosts")["hosts"]}
        cid = self.add_check(hosts["xxxx-srv"])
        forged = report("yyy-srv", checks=[{"id": cid, "ok": False, "error": "sahte"}] * 3)
        self.call("/api/agent/report", forged, token=self.yyy["token"])
        self.assertEqual(self.call("/api/checks")["checks"][0]["state"], "unknown")
        self.assertEqual(self.open_alerts(), {})
        self.assertEqual(self.call("/api/agent/report", report("yyy-srv"), token=self.yyy["token"])["checks"], [])

    def test_check_validation_and_permissions(self):
        self.call("/api/agent/report", report("xxxx-srv"), token=self.xxxx["token"])
        self.call("/api/agent/report", report("yyy-srv"), token=self.yyy["token"])
        hosts = {h["hostname"]: h["id"] for h in self.call("/api/hosts")["hosts"]}
        bad = [{"type": "icmp"}, {"target": "ftp://x"}, {"target": "https://kullanici:parola@x/"},
               {"type": "tcp", "target": "10.0.0.5"}, {"type": "tcp", "target": "10.0.0.5:99999"},
               {"type": "tcp", "target": "a b:22"}, {"name": ""}, {"expect_status": 999}, {"host_id": 9999}]
        for fields in bad:
            body = {"host_id": hosts["xxxx-srv"], "name": "x", "type": "http", "target": "https://x/"}
            body.update(fields)
            self.assertIn(self.status("/api/checks", body), (400, 404), fields)
        tcp = self.add_check(hosts["xxxx-srv"], name="PostgreSQL", type="tcp", target="10.0.0.5:5432")
        self.make_user("yyy.operator", "operator", [self.yyy])
        self.make_user("izleyici", "viewer", all_companies=True)
        self.as_user("yyy.operator")
        self.assertEqual(self.call("/api/checks")["checks"], [])
        self.assertEqual(self.status("/api/checks", {"host_id": hosts["xxxx-srv"], "name": "x", "type": "tcp",
                                                     "target": "10.0.0.1:22"}), 404)
        self.assertEqual(self.status(f"/api/checks/{tcp}", {"enabled": False}), 404)
        self.assertEqual(self.status(f"/api/checks/{tcp}/delete", {}), 404)
        own = self.add_check(hosts["yyy-srv"], name="Site", target="http://10.1.0.5/")
        self.call(f"/api/checks/{own}", {"enabled": False})
        self.assertEqual(self.call("/api/checks")["checks"][0]["state"], "off")
        self.as_user("izleyici")
        self.assertEqual(len(self.call("/api/checks")["checks"]), 2)
        self.assertEqual(self.status(f"/api/checks/{tcp}/delete", {}), 403)

    # ---------------------------------------------------------------- uyarılar ve Telegram
    def test_critical_disk_alert_notifies_and_resolves(self):
        self.call("/api/agent/report", report(disk=95), token=self.xxxx["token"])
        alert = self.open_alerts()["disk:/"]
        self.assertEqual(alert["severity"], "crit")
        msgs = self.messages()
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["chat_id"], "-100default")
        self.assertIn("KRİTİK", msgs[0]["text"])
        self.assertIn("XXXX", msgs[0]["text"])
        self.assertTrue(FakeTelegram.received[0][0].endswith("/bot123:ABC/sendMessage"))

        self.call("/api/agent/report", report(disk=50), token=self.xxxx["token"])
        self.assertNotIn("disk:/", self.open_alerts())
        self.assertIn("ÇÖZÜLDÜ", self.messages()[-1]["text"])

    def test_warning_does_not_page_but_escalation_does(self):
        self.call("/api/agent/report", report(disk=85), token=self.xxxx["token"])
        self.assertEqual(self.open_alerts()["disk:/"]["severity"], "warn")
        self.assertEqual(self.messages(), [])
        self.call("/api/agent/report", report(disk=93), token=self.xxxx["token"])
        self.assertEqual(len(self.messages()), 1)

    def test_company_specific_chat_and_reminder_until_ack(self):
        self.call(f"/api/companies/{self.yyy['id']}", {"telegram_chat_id": "-100yyy"})
        self.call("/api/agent/report", report(disk=95), token=self.yyy["token"])
        self.assertEqual(self.messages()[0]["chat_id"], "-100yyy")
        self.engine.tick(time.time() + 60)          # henüz erken
        self.assertEqual(len(self.messages()), 1)
        self.db.write("UPDATE alerts SET notified_at=notified_at-1000")
        self.db.write("UPDATE hosts SET last_seen=?", (time.time(),))
        self.engine.tick()
        self.assertEqual(len(self.messages()), 2)
        self.assertIn("onay bekliyor", self.messages()[1]["text"])
        alert_id = self.open_alerts()["disk:/"]["id"]
        self.call(f"/api/alerts/{alert_id}/ack", {})
        self.db.write("UPDATE alerts SET notified_at=notified_at-1000")
        self.engine.tick()
        self.assertEqual(len(self.messages()), 2)   # onaylandı, tekrar yok

    def test_offline_host_raises_and_clears(self):
        self.call("/api/agent/report", report(), token=self.xxxx["token"])
        self.engine.tick(time.time() + 300)
        self.assertEqual(self.open_alerts()["offline"]["severity"], "crit")
        self.call("/api/agent/report", report(), token=self.xxxx["token"])
        self.assertNotIn("offline", self.open_alerts())

    # ---------------------------------------------------------------- bağlantı analizi
    def test_port_scan_detection_and_analysis(self):
        conns = [{"src": "203.0.113.9", "port": p, "count": 1, "open": p in (22, 443)} for p in range(20, 45)]
        conns.append({"src": "10.0.0.7", "port": 443, "count": 12, "open": True})
        self.call("/api/agent/report", report(connections=conns), token=self.xxxx["token"])
        alerts = self.open_alerts()
        self.assertIn("scan:203.0.113.9", alerts)
        self.assertNotIn("scan:10.0.0.7", alerts)
        data = self.call("/api/connections?hours=1")
        self.assertEqual(data["totals"]["attempts"], 37)
        self.assertEqual(data["totals"]["closed"], 24)
        top = {s["src"]: s for s in data["sources"]}
        self.assertEqual(top["203.0.113.9"]["ports"], 25)
        self.assertFalse(top["203.0.113.9"]["internal"])
        self.assertTrue(top["10.0.0.7"]["internal"])
        self.assertEqual(data["ports"][0]["port"], 443)

    def test_ssh_brute_force_detection(self):
        auth = [{"src": "198.51.100.4", "user": "root", "result": "fail", "count": 8},
                {"src": "198.51.100.4", "user": "admin", "result": "fail", "count": 4},
                {"src": "10.0.0.9", "user": "deploy", "result": "ok", "count": 1}]
        self.call("/api/agent/report", report(auth=auth), token=self.xxxx["token"])
        self.assertIn("brute:198.51.100.4", self.open_alerts())
        data = self.call("/api/connections?hours=1")
        self.assertEqual(data["totals"]["ssh_fail"], 12)
        self.assertEqual(data["totals"]["ssh_ok"], 1)
        self.assertEqual(data["users"][0]["user"], "root")

    def test_windows_agent_report_shape(self):
        """Windows ajanının gönderdiği biçim: sürücü harfli diskler, audit modu, portsuz oturum açma."""
        win = report("WIN-DC01", capture_mode="audit",
                     connections=[{"src": "10.0.0.7", "port": 3389, "count": 2, "open": True},
                                  {"src": "203.0.113.9", "port": 445, "count": 3, "open": False}],
                     auth=[{"src": "198.51.100.4", "user": "Administrator", "result": "fail", "count": 11, "service": "windows"},
                           {"src": "10.0.0.7", "user": "ayse", "result": "ok", "count": 1, "service": "windows", "port": 3389}])
        win["metrics"]["disks"] = [{"mount": "C:", "total": 100, "used": 95, "pct": 95.0}]
        del win["metrics"]["load1"]
        self.call("/api/agent/report", win, token=self.xxxx["token"])
        alerts = self.open_alerts()
        self.assertIn("disk:C:", alerts)
        self.assertIn("brute:198.51.100.4", alerts)
        host = self.call("/api/hosts")["hosts"][0]
        self.assertEqual((host["hostname"], host["capture_mode"]), ("WIN-DC01", "audit"))
        recent = {(e["kind"], e["src"]): e["port"] for e in self.call("/api/connections?hours=1")["recent"]}
        self.assertIsNone(recent[("ssh_fail", "198.51.100.4")])
        self.assertEqual(recent[("ssh_ok", "10.0.0.7")], 3389)

    def test_malformed_agent_data_is_dropped(self):
        bad = report(connections=[{"src": "<script>", "port": 22, "count": 1}, {"src": "1.2.3.4", "port": 99999, "count": 1},
                                  "x", {"src": "1.2.3.4", "port": 80, "count": 2}],
                     devices=[{"ip": "10.0.0.1", "mac": "zz"}, {"ip": "nope", "mac": "aa:bb:cc:dd:ee:ff"}])
        self.call("/api/agent/report", bad, token=self.xxxx["token"])
        self.assertEqual(self.call("/api/connections?hours=1")["totals"]["attempts"], 2)
        self.assertEqual(self.call("/api/devices")["devices"], [])
        self.assertEqual(self.status("/api/agent/report", {"host": {}}, token=self.xxxx["token"]), 400)

    # ---------------------------------------------------------------- ağ cihazları
    def test_device_discovery_new_device_and_watch(self):
        company, now = self.company(self.xxxx), time.time()
        gw = {"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:01", "hostname": "gw", "gateway": True}
        printer = {"ip": "10.0.0.20", "mac": "aa:aa:aa:aa:aa:02", "hostname": "yazici"}
        self.engine.ingest(company, report(devices=[gw, printer]), now - 2000)
        self.assertEqual(self.open_alerts(), {})    # ilk tarama taban çizgisi
        laptop = {"ip": "10.0.0.33", "mac": "aa:aa:aa:aa:aa:03", "hostname": ""}
        self.engine.ingest(company, report(devices=[gw, printer, laptop]), now - 1500)
        self.assertEqual(self.open_alerts()["newdev:aa:aa:aa:aa:aa:03"]["severity"], "info")

        devices = {d["mac"]: d for d in self.call("/api/devices")["devices"]}
        self.assertEqual(len(devices), 3)
        self.assertTrue(devices["aa:aa:aa:aa:aa:01"]["is_gateway"])
        self.call(f"/api/devices/{devices['aa:aa:aa:aa:aa:02']['id']}", {"watched": True, "label": "Muhasebe yazıcısı"})
        self.engine.ingest(company, report(devices=[gw, laptop]), now)   # yazıcı artık yok
        alert = self.open_alerts()["device:aa:aa:aa:aa:aa:02"]
        self.assertEqual(alert["severity"], "crit")
        self.assertIn("Muhasebe yazıcısı", alert["title"])
        devices = {d["mac"]: d for d in self.call("/api/devices")["devices"]}
        self.assertFalse(devices["aa:aa:aa:aa:aa:02"]["online"])
        self.assertTrue(devices["aa:aa:aa:aa:aa:01"]["online"])
        self.engine.ingest(company, report(devices=[gw, laptop, printer]), now + 5)
        self.assertNotIn("device:aa:aa:aa:aa:aa:02", self.open_alerts())

    def test_settings_hide_bot_token(self):
        view = self.call("/api/settings")
        self.assertNotIn("telegram_bot_token", view)
        self.assertEqual(view["telegram_bot_token_hint"], ":ABC")
        self.call("/api/settings", {"telegram_bot_token": "", "disk_crit": "97"})
        self.assertEqual(self.db.get("telegram_bot_token"), "123:ABC")
        self.assertEqual(self.db.num("disk_crit"), 97)
        self.assertEqual(self.status("/api/settings", {"disk_crit": "abc"}), 400)
        self.assertEqual(self.call("/api/settings/test", {})["sent"], ["telegram"])


def syn_frame(src, dst, dport, flags=0x02, vlan=False):
    eth = b"\x00" * 12 + (b"\x81\x00\x00\x01" if vlan else b"") + b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    tcp = struct.pack("!HHIIBBHHH", 40000, dport, 0, 0, 0x50, flags, 1024, 0, 0)
    return eth + ip + tcp


class AgentTest(unittest.TestCase):
    def test_parse_syn(self):
        self.assertEqual(agent.parse_syn(syn_frame("1.2.3.4", "10.0.0.5", 3389)), ("1.2.3.4", "10.0.0.5", 3389))
        self.assertEqual(agent.parse_syn(syn_frame("1.2.3.4", "10.0.0.5", 22, vlan=True)), ("1.2.3.4", "10.0.0.5", 22))
        self.assertIsNone(agent.parse_syn(syn_frame("1.2.3.4", "10.0.0.5", 22, flags=0x12)))  # SYN+ACK: yanıt
        self.assertIsNone(agent.parse_syn(syn_frame("1.2.3.4", "10.0.0.5", 22, flags=0x10)))  # ACK
        self.assertIsNone(agent.parse_syn(b"\x00" * 20))

    def test_tcp_table(self):
        header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        v4 = header + ("   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n"
                       "   1: 0500000A:0016 0700000A:D431 01 00000000:00000000 00:00000000 00000000     0        0 2 1\n")
        v6 = header + ("   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0 0 3\n"
                       "   1: 0000000000000000FFFF00000500000A:01BB 0000000000000000FFFF00000900000A:C000 01 0 0 0 0 0 0 0 4\n")
        listening, established = agent.read_tcp_table([v4, v6])
        self.assertEqual(listening, {22, 443})
        if sys.byteorder == "little":
            self.assertEqual(established, [("10.0.0.7", 54321, 22), ("10.0.0.9", 49152, 443)])

    def test_arp_and_auth_parsing(self):
        arp = ("IP address       HW type     Flags       HW address            Mask     Device\n"
               "10.0.0.1         0x1         0x2         AA:BB:CC:00:00:01     *        eth0\n"
               "10.0.0.50        0x1         0x0         00:00:00:00:00:00     *        eth0\n")
        self.assertEqual(agent.parse_arp(arp), [("10.0.0.1", "aa:bb:cc:00:00:01", "eth0")])
        lines = ["sshd[1]: Failed password for invalid user admin from 198.51.100.4 port 5 ssh2",
                 "sshd[1]: Failed password for root from 198.51.100.4 port 6 ssh2",
                 "sshd[1]: Failed password for root from 198.51.100.4 port 7 ssh2",
                 "sshd[2]: Accepted publickey for deploy from 10.0.0.9 port 8 ssh2: ED25519 SHA256:x",
                 "sshd[3]: Connection closed by 1.1.1.1"]
        self.assertEqual(agent.parse_auth_lines(lines), {
            ("198.51.100.4", "admin", "fail"): 1, ("198.51.100.4", "root", "fail"): 2, ("10.0.0.9", "deploy", "ok"): 1})

    def test_meminfo_and_cpu(self):
        mem = agent.read_meminfo("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 250 kB\n")
        self.assertEqual((mem["mem_total"], mem["mem_used"], mem["mem_pct"]), (1024000, 768000, 75.0))
        self.assertEqual(agent.read_cpu_times("cpu  10 0 10 70 10 0 0 0 0 0\n"), (80, 100))

    def test_run_check_against_local_services(self):
        class Health(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200 if self.path == "/ok" else 503)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass
        srv = HTTPServer(("127.0.0.1", 0), Health)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_port
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]
        closed.close()
        try:
            results = agent.run_checks([
                {"id": 1, "type": "tcp", "target": f"127.0.0.1:{port}"},
                {"id": 2, "type": "tcp", "target": f"127.0.0.1:{closed_port}"},
                {"id": 3, "type": "http", "target": f"http://127.0.0.1:{port}/ok"},
                {"id": 4, "type": "http", "target": f"http://127.0.0.1:{port}/hata"},
                {"id": 5, "type": "http", "target": f"http://127.0.0.1:{port}/hata", "expect_status": 503},
                {"id": 6, "type": "ping", "target": "x"}, "bozuk"])
        finally:
            srv.shutdown()
            srv.server_close()
        by_id = {r["id"]: r for r in results}
        self.assertEqual([by_id[i]["ok"] for i in range(1, 7)], [True, False, True, False, True, False])
        self.assertEqual(by_id[2]["error"], "Bağlantı reddedildi")
        self.assertEqual((by_id[4]["status_code"], by_id[4]["error"]), (503, "HTTP 503"))
        self.assertTrue(all("latency_ms" in r for r in results))

    @unittest.skipUnless(shutil.which("openssl"), "openssl gerekli")
    def test_https_check_reports_certificate_expiry(self):
        import ssl
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                            "-days", "20", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                           check=True, capture_output=True)

            class Ok(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

                def log_message(self, *args):
                    pass
            srv = HTTPServer(("127.0.0.1", 0), Ok)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            url = f"https://localhost:{srv.server_port}/"
            try:
                untrusted = agent.run_check({"id": 1, "type": "http", "target": url})
                unverified = agent.run_check({"id": 2, "type": "http", "target": url, "verify": False})
                trusted = agent.run_check({"id": 3, "type": "http", "target": url, "_cafile": cert})
            finally:
                srv.shutdown()
                srv.server_close()
        self.assertFalse(untrusted["ok"])
        self.assertIn("Sertifika doğrulanamadı", untrusted["error"])
        self.assertTrue(unverified["ok"])
        self.assertNotIn("cert_days", unverified)
        self.assertTrue(trusted["ok"])
        self.assertTrue(19 <= trusted["cert_days"] <= 20, trusted)

    def test_monitor_ignores_own_addresses(self):
        mon = agent.ConnectionMonitor.__new__(agent.ConnectionMonitor)
        mon.local_ips, mon.counts, mon.lock = {"10.0.0.5"}, {}, threading.Lock()
        for src in ("10.0.0.5", "127.0.0.1", "1.2.3.4", "1.2.3.4"):
            mon.record(src, 22)
        self.assertEqual(mon.drain(), {("1.2.3.4", 22): 2})
        self.assertEqual(mon.drain(), {})


if __name__ == "__main__":
    unittest.main()

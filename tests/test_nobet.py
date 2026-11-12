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
from manager import notify, qr, totp  # noqa: E402
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

    def login(self, username, password, code=None):
        saved, self.cookie = self.cookie, ""
        try:
            body = {"username": username, "password": password}
            if code is not None:
                body["code"] = code
            resp = self.call("/api/login", body, raw=True)
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

    # ---------------------------------------------------------------- iki adımlı doğrulama
    def error(self, path, body):
        """İsteğin hata yanıtını (durum, gövde) olarak döndürür."""
        try:
            self.call(path, body)
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read())
        self.fail("hata bekleniyordu")

    def enroll(self, password="parola-12345"):
        """Geçerli oturumdaki kullanıcı için iki adımlı doğrulamayı kurar; (gizli anahtar, kurtarma kodları)."""
        secret = self.call("/api/me/totp_setup", {"password": password})["secret"]
        codes = self.call("/api/me/totp_enable", {"code": totp.code_at(secret, int(time.time() // 30))})["recovery_codes"]
        return secret, codes

    def test_totp_matches_rfc6238_vectors(self):
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual([totp.code_at(secret, t // 30) for t in (59, 1111111109, 2000000000)],
                         ["287082", "081804", "279037"])
        self.assertEqual(totp.verify(secret, "287 082", now=59), 1)
        self.assertEqual(totp.verify(secret, "287082", now=89), 1)           # bir adım saat kayması
        self.assertIsNone(totp.verify(secret, "287082", now=150))            # süresi geçmiş
        self.assertIsNone(totp.verify(secret, "287082", last_step=1, now=59))  # aynı kod ikinci kez
        self.assertIsNone(totp.verify(secret, "abc", now=59))

    def test_two_factor_enrollment_and_login(self):
        self.make_user("ayse", "operator", [self.xxxx])
        self.as_user("ayse")
        self.assertEqual(self.status("/api/me/totp_setup", {"password": "yanlis"}), 400)
        setup = self.call("/api/me/totp_setup", {"password": "parola-12345"})
        secret = setup["secret"]
        # QR kod, uygulamanın okuyacağı adresi taşır.
        decoded = qr_decode([[int(ch) for ch in row] for row in setup["qr"]])
        self.assertEqual(decoded, setup["uri"])
        self.assertIn(f"secret={secret}", decoded)
        self.assertIn("Nobet%3Aayse", decoded)
        self.assertFalse(self.call("/api/me")["totp_enabled"])                # kod doğrulanmadan etkin olmaz
        self.assertEqual(self.status("/api/me/totp_enable", {"code": "000000"}), 400)
        now_step = int(time.time() // 30)
        codes = self.call("/api/me/totp_enable", {"code": totp.code_at(secret, now_step)})["recovery_codes"]
        me = self.call("/api/me")
        self.assertEqual((me["totp_enabled"], me["recovery_codes_left"], len(codes)), (True, 8, 8))
        self.assertNotIn(codes[0], json.dumps(self.db.q("SELECT * FROM recovery_codes")))   # yalnızca özet saklanır

        # Parola tek başına yetmez; kod istenir ve bu bir hata sayılmaz.
        status, body = self.error_login("ayse", "parola-12345")
        self.assertEqual((status, body.get("totp_required")), (401, True))
        status, body = self.error_login("ayse", "parola-12345", "000000")
        self.assertEqual((status, body.get("totp_required")), (401, True))
        # Kurulumda kullanılan kod tekrar kullanılamaz; sonraki adımın kodu geçerlidir.
        self.assertEqual(self.error_login("ayse", "parola-12345", totp.code_at(secret, now_step))[0], 401)
        self.cookie = self.login("ayse", "parola-12345", totp.code_at(secret, now_step + 1))
        self.assertEqual(self.status("/api/hosts"), 200)
        # Kurtarma kodu bir kez çalışır.
        self.cookie = self.login("ayse", "parola-12345", codes[0].upper().replace("-", " "))
        self.assertEqual(self.call("/api/me")["recovery_codes_left"], 7)
        self.assertEqual(self.error_login("ayse", "parola-12345", codes[0])[0], 401)
        # Kapatmak için parola ve kod gerekir.
        self.assertEqual(self.status("/api/me/totp_disable", {"password": "parola-12345", "code": "000000"}), 400)
        self.call("/api/me/totp_disable", {"password": "parola-12345", "code": codes[1]})
        self.assertFalse(self.call("/api/me")["totp_enabled"])
        self.cookie = self.login("ayse", "parola-12345")

    def error_login(self, username, password, code=None):
        saved, self.cookie = self.cookie, ""
        try:
            body = {"username": username, "password": password}
            if code is not None:
                body["code"] = code
            return self.error("/api/login", body)
        finally:
            self.cookie = saved

    def test_two_factor_required_setting_and_admin_reset(self):
        uid = self.make_user("mehmet", "viewer", [self.xxxx])
        admin_secret, _ = self.enroll("gizli-parola")
        self.call("/api/settings", {"require_2fa": "1"})
        admin_cookie = self.cookie
        self.as_user("mehmet")
        me = self.call("/api/me")
        self.assertEqual((me["must_setup_2fa"], me["totp_enabled"]), (True, False))
        try:
            self.call("/api/hosts")
            self.fail("kurulum yapılmadan erişim engellenmeliydi")
        except urllib.error.HTTPError as err:
            self.assertEqual((err.code, json.loads(err.read()).get("setup_2fa")), (403, True))
        secret, _ = self.enroll()
        self.assertEqual(self.status("/api/hosts"), 200)                      # kurulumdan sonra erişim açılır
        self.assertFalse(self.call("/api/me")["must_setup_2fa"])
        # Telefonunu kaybeden kullanıcı için yönetici sıfırlar; oturumları kapanır.
        mehmet_cookie = self.cookie
        self.cookie = admin_cookie
        self.assertTrue([u for u in self.call("/api/users")["users"] if u["id"] == uid][0]["totp_enabled"])
        self.call(f"/api/users/{uid}", {"reset_totp": True})
        self.cookie = mehmet_cookie
        self.assertEqual(self.status("/api/me"), 401)
        self.cookie = admin_cookie
        self.cookie = self.login("mehmet", "parola-12345")                    # artık kod istenmez
        self.assertTrue(self.call("/api/me")["must_setup_2fa"])
        self.cookie = admin_cookie
        actions = [(e["action"], e["detail"]) for e in self.call("/api/audit")["entries"]]
        self.assertIn(("user.update", "iki adımlı doğrulama sıfırlandı"), actions)
        self.assertIn(("auth.totp_enabled", ""), actions)
        dump = json.dumps(self.call("/api/audit")["entries"]) + json.dumps(self.call("/api/users"))
        for secret_value in (secret, admin_secret):
            self.assertNotIn(secret_value, dump)

    def test_wrong_codes_are_rate_limited_per_account(self):
        self.make_user("ayse", "operator", [self.xxxx])
        self.as_user("ayse")
        self.enroll()
        for _ in range(5):
            self.assertEqual(self.error_login("ayse", "parola-12345", "123456")[0], 401)
        self.assertEqual(self.error_login("ayse", "parola-12345", "123456")[0], 429)
        failed = [e for e in self.db.q("SELECT * FROM audit_log WHERE action='auth.login_failed'")]
        self.assertEqual((len(failed), failed[0]["detail"]), (5, "doğrulama kodu hatalı"))

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

    # ---------------------------------------------------------------- veri sızıntısı izleme
    def test_usb_and_watched_folder_events(self):
        first = self.call("/api/agent/report", report("fs-01"), token=self.xxxx["token"])
        self.assertEqual(first["watch_paths"], [])
        host_id = self.call("/api/hosts")["hosts"][0]["id"]
        wid = self.call("/api/watchpaths", {"host_id": host_id, "path": "/srv/paylasim/muhasebe/", "label": "Muhasebe"})["id"]
        sent = self.call("/api/agent/report", report("fs-01"), token=self.xxxx["token"])["watch_paths"]
        self.assertEqual(sent, [{"id": wid, "path": "/srv/paylasim/muhasebe"}])

        def send(**dlp):
            self.call("/api/agent/report", report("fs-01", dlp=dlp), token=self.xxxx["token"])
        send(usb=[{"action": "insert", "vendor": "Kingston", "model": "DataTraveler", "serial": "AB12", "size": 32 * 1024**3}],
             watch_status=[{"id": wid, "ok": True, "detail": "3 klasör izleniyor"}],
             files=[{"watch_id": wid, "action": "read", "path": "/srv/paylasim/muhasebe/bordro.xlsx", "user": "", "count": 4},
                    {"watch_id": wid, "action": "write", "path": "/srv/paylasim/muhasebe/2026/fatura.pdf", "user": "", "count": 1},
                    # Kabul edilmemesi gerekenler: klasör dışı yol, yukarı çıkma, bilinmeyen izleme, geçersiz işlem
                    {"watch_id": wid, "action": "read", "path": "/etc/shadow", "count": 1},
                    {"watch_id": wid, "action": "read", "path": "/srv/paylasim/muhasebe/../gizli", "count": 1},
                    {"watch_id": 9999, "action": "read", "path": "/srv/paylasim/muhasebe/x", "count": 1},
                    {"watch_id": wid, "action": "exec", "path": "/srv/paylasim/muhasebe/x", "count": 1}, "bozuk"])
        alert = self.open_alerts()["usb:AB12"]
        self.assertEqual((alert["severity"], alert["title"]), ("warn", "USB depolama takıldı: Kingston DataTraveler"))
        self.assertIn("32.0 GB", alert["detail"])
        data = self.call("/api/dlp?hours=1")
        self.assertEqual(data["totals"], {"usb": 1, "files": 5, "deletes": 0, "reads": 4, "writes": 1})
        self.assertEqual(data["usb"][0]["device"], "Kingston DataTraveler")
        self.assertEqual({r["path"] for r in data["recent"]},
                         {"/srv/paylasim/muhasebe/bordro.xlsx", "/srv/paylasim/muhasebe/2026/fatura.pdf"})
        watch = data["watch_paths"][0]
        self.assertEqual((watch["status"], watch["detail"], watch["events_24h"]), ("ok", "3 klasör izleniyor", 5))

        # Toplu silme: eşik 50 -> kritik uyarı ve Telegram
        send(files=[{"watch_id": wid, "action": "delete", "path": f"/srv/paylasim/muhasebe/d{i}.doc", "user": "ayse", "count": 1}
                    for i in range(60)])
        mass = self.open_alerts()["massdel:ayse"]
        self.assertEqual(mass["severity"], "crit")
        self.assertIn("60 silme", mass["detail"])
        self.assertIn("Toplu dosya silme: ayse", self.messages()[-1]["text"])
        self.assertEqual(self.call("/api/dlp?hours=1")["users"][0]["user"], "ayse")

        self.call(f"/api/watchpaths/{wid}/delete", {})
        self.assertEqual(self.call("/api/agent/report", report("fs-01"), token=self.xxxx["token"])["watch_paths"], [])
        actions = [e["action"] for e in self.call("/api/audit?area=watch")["entries"]]
        self.assertEqual(actions, ["watch.delete", "watch.create"])

    def test_dlp_permissions_isolation_and_validation(self):
        self.call("/api/agent/report", report("xxxx-fs"), token=self.xxxx["token"])
        self.call("/api/agent/report", report("yyy-fs"), token=self.yyy["token"])
        hosts = {h["hostname"]: h["id"] for h in self.call("/api/hosts")["hosts"]}
        for path in ("/", "/srv", "/etc/ssl/private", "/proc/1", "srv/x", "C:\\", "C:\\Windows\\System32",
                     "D:\\a\\..\\b", "/srv/a/../b", "x" * 300):
            self.assertEqual(self.status("/api/watchpaths", {"host_id": hosts["xxxx-fs"], "path": path}), 400, path)
        wid = self.call("/api/watchpaths", {"host_id": hosts["xxxx-fs"], "path": "D:\\Paylasim\\IK\\"})["id"]
        self.assertEqual(self.status("/api/watchpaths", {"host_id": hosts["xxxx-fs"], "path": "D:\\Paylasim\\IK"}), 409)
        # Windows yolu: büyük/küçük harf farkı kabul edilir; başka sunucunun ajanı bu izleme için kayıt gönderemez.
        entry = {"watch_id": wid, "action": "read", "path": "d:\\paylasim\\ik\\ozluk.docx", "user": "SIRKET\\mehmet", "count": 2}
        self.call("/api/agent/report", report("yyy-fs", dlp={"files": [entry]}), token=self.yyy["token"])
        self.assertEqual(self.call("/api/dlp?hours=1")["totals"]["files"], 0)
        self.call("/api/agent/report", report("xxxx-fs", dlp={"files": [entry]}), token=self.xxxx["token"])
        self.assertEqual(self.call("/api/dlp?hours=1")["users"][0]["user"], "SIRKET\\mehmet")

        self.make_user("yyy.operator", "operator", [self.yyy])
        self.make_user("izleyici", "viewer", all_companies=True)
        self.as_user("yyy.operator")
        self.assertEqual(self.call("/api/dlp?hours=1")["totals"]["files"], 0)      # yalnızca kendi şirketi
        self.assertEqual(self.call("/api/dlp?hours=1")["watch_paths"], [])
        self.assertEqual(self.status("/api/watchpaths", {"host_id": hosts["xxxx-fs"], "path": "/srv/a/b"}), 404)
        self.assertEqual(self.status(f"/api/watchpaths/{wid}/delete", {}), 404)
        self.assertEqual(self.status("/api/watchpaths", {"host_id": hosts["yyy-fs"], "path": "/srv/a/b"}), 201)
        self.as_user("izleyici")
        self.assertEqual(self.status("/api/dlp"), 403)                               # çalışan etkinliği izleyiciye kapalı
        self.assertEqual(self.status("/api/watchpaths", {"host_id": hosts["yyy-fs"], "path": "/srv/a/c"}), 403)

    def test_dlp_events_expire_after_retention(self):
        company = self.company(self.xxxx)
        old = time.time() - 40 * 86400
        self.engine.ingest(company, report("fs", dlp={"usb": [{"action": "insert", "model": "Eski"}]}), old)
        self.engine.ingest(company, report("fs", dlp={"usb": [{"action": "insert", "model": "Yeni"}]}))
        self.engine.tick()
        self.assertEqual([r["device"] for r in self.db.q("SELECT device FROM dlp_events")], ["Yeni"])

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


def qr_decode(grid):
    """Testler için bağımsız QR çözücü: üretecin yardımcılarını kullanmadan, standarttaki kurallarla
    matrisi okur; yapı desenlerini, biçim bilgisini ve her bloğun Reed-Solomon sendromlarını doğrular."""
    size = len(grid)
    version = (size - 17) // 4
    assert size == version * 4 + 17 and all(len(row) == size for row in grid)
    finder = ["1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111"]
    for top, left in ((0, 0), (0, size - 7), (size - 7, 0)):
        assert ["".join(map(str, grid[top + r][left:left + 7])) for r in range(7)] == finder, "bulucu desen"
    assert all(grid[6][i] == (i + 1) % 2 and grid[i][6] == (i + 1) % 2 for i in range(8, size - 8)), "zamanlama"
    assert grid[size - 8][8] == 1, "koyu modül"

    # Biçim bilgisi: iki kopya aynı olmalı ve BCH(15,5) kodunu sağlamalı.
    first = [grid[i][8] for i in range(6)] + [grid[7][8], grid[8][8], grid[8][7]] + [grid[8][14 - i] for i in range(9, 15)]
    second = [grid[8][size - 1 - i] for i in range(8)] + [grid[size - 15 + i][8] for i in range(8, 15)]
    assert first == second, "biçim kopyaları"
    value = sum(bit << i for i, bit in enumerate(first)) ^ 0x5412
    remainder = value
    for bit in range(14, 9, -1):
        if remainder >> bit & 1:
            remainder ^= 0x537 << (bit - 10)
    assert remainder == 0, "biçim BCH"
    assert value >> 13 == 0, "hata düzeltme seviyesi M olmalı"
    mask = value >> 10 & 7

    # İşlev modülleri (veri taşımayan alanlar)
    func = [[False] * size for _ in range(size)]
    for y in range(size):
        for x in range(size):
            if (x <= 8 and y <= 8) or (x >= size - 8 and y <= 8) or (x <= 8 and y >= size - 8) or x == 6 or y == 6:
                func[y][x] = True
    centers = [] if version == 1 else [6, size - 7] if version < 7 else [6, (size - 1) // 2, size - 7]
    for cy in centers:
        for cx in centers:
            if (cx == 6 and cy == 6) or (cx == 6 and cy == size - 7) or (cx == size - 7 and cy == 6):
                continue
            assert ["".join(map(str, grid[cy + r][cx - 2:cx + 3])) for r in range(-2, 3)] == \
                ["11111", "10001", "10101", "10001", "11111"], "hizalama deseni"
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    func[cy + dy][cx + dx] = True
    if version >= 7:
        for a in range(size - 11, size - 8):
            for b in range(6):
                func[b][a] = func[a][b] = True
        info = sum(grid[i // 3][size - 11 + i % 3] << i for i in range(18))
        assert info == sum(grid[size - 11 + i % 3][i // 3] << i for i in range(18)) and info >> 12 == version, "sürüm bilgisi"

    conditions = [lambda i, j: (i + j) % 2 == 0, lambda i, j: i % 2 == 0, lambda i, j: j % 3 == 0,
                  lambda i, j: (i + j) % 3 == 0, lambda i, j: (i // 2 + j // 3) % 2 == 0,
                  lambda i, j: i * j % 2 + i * j % 3 == 0, lambda i, j: (i * j % 2 + i * j % 3) % 2 == 0,
                  lambda i, j: ((i + j) % 2 + i * j % 3) % 2 == 0]   # i = satır, j = sütun
    bits, col, upward = [], size - 1, True
    while col > 0:
        if col == 6:
            col -= 1
        for row in (range(size - 1, -1, -1) if upward else range(size)):
            for c in (col, col - 1):
                if not func[row][c]:
                    bits.append(grid[row][c] ^ (1 if conditions[mask](row, c) else 0))
        col -= 2
        upward = not upward
    table = {1: (26, 10, [16]), 2: (44, 16, [28]), 3: (70, 26, [44]), 4: (100, 18, [32] * 2), 5: (134, 24, [43] * 2),
             6: (172, 16, [27] * 4), 7: (196, 18, [31] * 4), 8: (242, 22, [38, 38, 39, 39]),
             9: (292, 22, [36, 36, 36, 37, 37]), 10: (346, 26, [43, 43, 43, 43, 44])}
    total, ec_len, sizes = table[version]
    assert len(bits) // 8 == total, "veri modülü sayısı"
    codewords = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, total * 8, 8)]
    blocks, position = [[] for _ in sizes], 0
    for i in range(max(sizes)):
        for b, block_size in enumerate(sizes):
            if i < block_size:
                blocks[b].append(codewords[position])
                position += 1
    ec = [[] for _ in sizes]
    for i in range(ec_len):
        for b in range(len(sizes)):
            ec[b].append(codewords[position])
            position += 1
    exp, value = [], 1
    for _ in range(255):
        exp.append(value)
        value = (value << 1) ^ (0x11D if value & 0x80 else 0)
    log = {v: i for i, v in enumerate(exp)}
    for block, extra in zip(blocks, ec):
        for power in range(ec_len):                      # geçerli kod sözcüğü her α^k için sıfır vermeli
            acc = 0
            for byte in block + extra:
                acc = (exp[(log[acc] + power) % 255] if acc else 0) ^ byte
            assert acc == 0, "Reed-Solomon sendromu"
    stream = "".join(format(byte, "08b") for block in blocks for byte in block)
    assert stream[:4] == "0100", "bayt kipi"
    length_bits = 8 if version <= 9 else 16
    length = int(stream[4:4 + length_bits], 2)
    start = 4 + length_bits
    return bytes(int(stream[start + 8 * i:start + 8 * i + 8], 2) for i in range(length)).decode("utf-8")


class QrTest(unittest.TestCase):
    def test_known_answers(self):
        # Yaygın eğitim örneği ("HELLO WORLD", 1-M) ve standarttaki biçim/sürüm bilgisi tabloları
        self.assertEqual(qr.rs_remainder([32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17], 10),
                         [196, 35, 39, 119, 235, 215, 231, 226, 93, 23])
        self.assertEqual([format(qr._bch(m, 0x537, 10) ^ 0x5412, "015b") for m in range(8)],
                         ["101010000010010", "101000100100101", "101111001111100", "101101101001011",
                          "100010111111001", "100000011001110", "100111110010111", "100101010100000"])
        self.assertEqual([format(qr._bch(v, 0x1F25, 12), "018b") for v in (7, 8, 9, 10)],
                         ["000111110010010100", "001000010110111100", "001001101010011001", "001010010011010011"])
        self.assertEqual([qr.capacity(v) for v in range(1, 11)], [14, 26, 42, 62, 84, 106, 122, 152, 180, 213])

    def test_round_trip_all_versions_and_masks(self):
        import random
        random.seed(11)
        texts = ["A", "x" * 14, "x" * 15, "y" * 42, "z" * 62, "w" * 84, "v" * 106, "u" * 122, "t" * 123,
                 "s" * 152, "r" * 180, "q" * 181, "p" * 213, "Türkçe: ğüşiöç İĞÜŞÖÇ"]
        texts += ["".join(chr(random.randint(32, 126)) for _ in range(random.randint(1, 213))) for _ in range(25)]
        sizes = set()
        for text in texts:
            for mask in range(8):
                grid = qr.encode(text, mask=mask)
                self.assertEqual(qr_decode(grid), text)
                sizes.add(len(grid))
            self.assertEqual(qr_decode(qr.encode(text)), text)          # otomatik maske seçimi
        self.assertEqual(sizes, {v * 4 + 17 for v in range(1, 11)})     # 1-10 arası tüm sürümler denendi
        with self.assertRaises(ValueError):
            qr.encode("x" * 214)

    def test_decoder_rejects_corruption(self):
        grid = qr.encode("otpauth://totp/Nobet%3Aadmin?secret=JBSWY3DPEHPK3PXP")
        grid[len(grid) - 3][len(grid) - 3] ^= 1                         # tek veri modülü bozuldu
        with self.assertRaises(AssertionError):
            qr_decode(grid)


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

    def test_usb_monitor_detects_insert_and_remove(self):
        with tempfile.TemporaryDirectory() as tmp:
            block = os.path.join(tmp, "sys", "block")
            os.makedirs(os.path.join(block, "sda"))                      # USB olmayan disk
            os.symlink(os.path.join(tmp, "devices", "pci0", "ata1", "host0"), os.path.join(block, "sda", "device"))
            os.makedirs(os.path.join(tmp, "devices", "pci0", "ata1", "host0"))
            mon = agent.UsbMonitor(block, interval=0)
            self.assertEqual(mon.drain(), [])
            usb = os.path.join(tmp, "devices", "pci0", "usb1", "1-2")
            target = os.path.join(usb, "1-2:1.0", "host6", "target6:0:0", "6:0:0:0")
            os.makedirs(target)
            for name, value in (("vendor", "Kingston\n"), ("model", "DataTraveler 3.0\n")):
                with open(os.path.join(target, name), "w") as f:
                    f.write(value)
            with open(os.path.join(usb, "serial"), "w") as f:
                f.write("E0D55EA574\n")
            os.makedirs(os.path.join(block, "sdb"))
            os.symlink(target, os.path.join(block, "sdb", "device"))
            with open(os.path.join(block, "sdb", "size"), "w") as f:
                f.write("1000\n")
            mon.poll()
            mon.poll()                                                    # aynı aygıt ikinci kez bildirilmez
            self.assertEqual(mon.drain(), [{"vendor": "Kingston", "model": "DataTraveler 3.0", "size": 512000,
                                            "serial": "E0D55EA574", "action": "insert"}])
            shutil.rmtree(os.path.join(block, "sdb"))
            mon.poll()
            self.assertEqual([(e["action"], e["serial"]) for e in mon.drain()], [("remove", "E0D55EA574")])

    def test_folder_watcher_reports_file_operations(self):
        def wait_for(watcher, expected, timeout=5):
            seen, deadline = {}, time.time() + timeout
            while time.time() < deadline and not expected <= set(seen):
                time.sleep(0.05)
                for (wid, action, path), n in watcher.drain().items():
                    seen[(action, os.path.basename(path))] = seen.get((action, os.path.basename(path)), 0) + n
            return seen
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "muhasebe")
            os.makedirs(os.path.join(root, "2026"))
            with open(os.path.join(root, "bordro.txt"), "w") as f:
                f.write("x")
            watcher = agent.FolderWatcher([{"id": 7, "path": root}, {"id": 8, "path": os.path.join(tmp, "yok")},
                                           {"id": 9, "path": "/"}])
            try:
                status = {st["id"]: st for st in watcher.statuses()}
                self.assertEqual((status[7]["ok"], status[7]["detail"]), (True, "2 klasör izleniyor"))
                self.assertEqual((status[8]["ok"], status[8]["detail"]), (False, "Klasör bulunamadı"))
                self.assertFalse(status[9]["ok"])
                with open(os.path.join(root, "bordro.txt")) as f:
                    f.read()
                with open(os.path.join(root, "2026", "fatura.txt"), "w") as f:
                    f.write("y")
                os.rename(os.path.join(root, "2026", "fatura.txt"), os.path.join(root, "2026", "fatura-son.txt"))
                os.remove(os.path.join(root, "bordro.txt"))
                os.makedirs(os.path.join(root, "yeni"))
                seen = wait_for(watcher, {("create", "yeni")})
                with open(os.path.join(root, "yeni", "gizli.txt"), "w") as f:   # sonradan oluşan klasör de izlenir
                    f.write("z")
                seen.update(wait_for(watcher, {("write", "gizli.txt")}))
            finally:
                watcher.close()
        for expected in (("read", "bordro.txt"), ("create", "fatura.txt"), ("write", "fatura.txt"),
                         ("move", "fatura.txt"), ("move", "fatura-son.txt"), ("delete", "bordro.txt"),
                         ("create", "yeni"), ("write", "gizli.txt")):
            self.assertIn(expected, seen)

    def test_monitor_ignores_own_addresses(self):
        mon = agent.ConnectionMonitor.__new__(agent.ConnectionMonitor)
        mon.local_ips, mon.counts, mon.lock = {"10.0.0.5"}, {}, threading.Lock()
        for src in ("10.0.0.5", "127.0.0.1", "1.2.3.4", "1.2.3.4"):
            mon.record(src, 22)
        self.assertEqual(mon.drain(), {("1.2.3.4", 22): 2})
        self.assertEqual(mon.drain(), {})


if __name__ == "__main__":
    unittest.main()

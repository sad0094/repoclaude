"""SQLite depolama katmanı: şema, bağlantı yönetimi ve küçük yardımcılar."""
import contextlib
import hashlib
import secrets
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS companies(
  id INTEGER PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  token_hint TEXT,
  telegram_chat_id TEXT DEFAULT '',
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts(
  id INTEGER PRIMARY KEY,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  agent_id TEXT NOT NULL,
  hostname TEXT, ip TEXT, os TEXT, cores INTEGER,
  agent_version TEXT, capture_mode TEXT,
  uptime_s REAL, cpu REAL, mem_pct REAL, mem_used INTEGER, mem_total INTEGER,
  load1 REAL, rx_bps REAL, tx_bps REAL,
  disks TEXT, listening TEXT, subnets TEXT,
  first_seen REAL, last_seen REAL, last_scan REAL,
  UNIQUE(company_id, agent_id)
);
CREATE TABLE IF NOT EXISTS metrics(
  host_id INTEGER NOT NULL, ts REAL NOT NULL,
  cpu REAL, mem_pct REAL, disk_pct REAL, rx_bps REAL, tx_bps REAL
);
CREATE INDEX IF NOT EXISTS metrics_host_ts ON metrics(host_id, ts);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  host_id INTEGER NOT NULL,
  ip TEXT NOT NULL, mac TEXT NOT NULL, hostname TEXT, iface TEXT,
  is_gateway INTEGER DEFAULT 0,
  label TEXT DEFAULT '', watched INTEGER DEFAULT 0,
  first_seen REAL, last_seen REAL,
  UNIQUE(company_id, mac)
);
CREATE TABLE IF NOT EXISTS conn_events(
  id INTEGER PRIMARY KEY,
  company_id INTEGER NOT NULL, host_id INTEGER NOT NULL, ts REAL NOT NULL,
  kind TEXT NOT NULL,            -- tcp | ssh_fail | ssh_ok
  src TEXT NOT NULL, port INTEGER, user TEXT, open INTEGER, count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS conn_company_ts ON conn_events(company_id, ts);
CREATE INDEX IF NOT EXISTS conn_host_ts ON conn_events(host_id, ts);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY,
  company_id INTEGER NOT NULL, host_id INTEGER,
  key TEXT NOT NULL, severity TEXT NOT NULL,   -- crit | warn | info
  title TEXT NOT NULL, detail TEXT,
  started_at REAL, last_seen REAL, resolved_at REAL, acked_at REAL,
  notified_at REAL, expire_after REAL
);
CREATE INDEX IF NOT EXISTS alerts_open ON alerts(company_id, resolved_at);
CREATE TABLE IF NOT EXISTS checks(
  id INTEGER PRIMARY KEY,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  host_id INTEGER NOT NULL,           -- kontrolü çalıştıran ajanın sunucusu
  name TEXT NOT NULL,
  type TEXT NOT NULL,                 -- tcp | http
  target TEXT NOT NULL,               -- tcp: host:port, http: URL
  expect_status INTEGER, slow_ms INTEGER, verify INTEGER DEFAULT 1, enabled INTEGER DEFAULT 1,
  status TEXT DEFAULT 'unknown',      -- ok | warn | crit | unknown
  latency_ms REAL, status_code INTEGER, cert_days REAL, detail TEXT DEFAULT '',
  fails INTEGER DEFAULT 0, checked_at REAL, changed_at REAL, created_at REAL
);
CREATE TABLE IF NOT EXISTS check_results(check_id INTEGER NOT NULL, ts REAL NOT NULL, ok INTEGER NOT NULL, latency_ms REAL);
CREATE INDEX IF NOT EXISTS check_results_idx ON check_results(check_id, ts);
CREATE TABLE IF NOT EXISTS watch_paths(
  id INTEGER PRIMARY KEY,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  host_id INTEGER NOT NULL,           -- klasörün bulunduğu sunucu
  path TEXT NOT NULL, label TEXT DEFAULT '',
  status TEXT DEFAULT 'unknown',      -- ok | error | unknown (ajanın bildirdiği)
  detail TEXT DEFAULT '', checked_at REAL, created_at REAL
);
CREATE TABLE IF NOT EXISTS dlp_events(
  id INTEGER PRIMARY KEY,
  company_id INTEGER NOT NULL, host_id INTEGER NOT NULL, ts REAL NOT NULL,
  kind TEXT NOT NULL,                 -- usb | file
  action TEXT NOT NULL,               -- usb: insert/remove; file: read/write/create/delete/move
  user TEXT DEFAULT '', path TEXT DEFAULT '', device TEXT DEFAULT '', detail TEXT DEFAULT '',
  watch_id INTEGER, count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS dlp_company_ts ON dlp_events(company_id, ts);
CREATE INDEX IF NOT EXISTS dlp_host_ts ON dlp_events(host_id, ts);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY,
  ts REAL NOT NULL,
  user_id INTEGER, username TEXT NOT NULL, role TEXT,   -- kullanıcı silinse de kayıt okunabilsin diye ad saklanır
  company_id INTEGER,
  action TEXT NOT NULL,        -- alan.eylem, ör. alert.ack
  target TEXT DEFAULT '', detail TEXT DEFAULT '', ip TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit_log(ts);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,                 -- admin | operator | viewer
  all_companies INTEGER DEFAULT 0,    -- 1: tüm şirketler (admin için her zaman geçerli)
  active INTEGER DEFAULT 1,
  created_at REAL, last_login REAL
);
CREATE TABLE IF NOT EXISTS user_companies(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, company_id)
);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
                                    created_at REAL, expires_at REAL);
"""

# Panelden değiştirilebilen ayarlar ve varsayılanları.
DEFAULTS = {
    "disk_warn": "80", "disk_crit": "90", "cpu_warn": "90", "mem_warn": "90",
    "offline_seconds": "120", "device_offline_seconds": "600",
    "scan_ports": "15", "brute_fails": "10", "check_fail_count": "2", "cert_warn_days": "14",
    "usb_alert": "1", "dlp_delete_threshold": "50", "dlp_read_threshold": "500", "dlp_retention_days": "30",
    "reminder_minutes": "15", "notify_warn": "0",
    "telegram_bot_token": "", "telegram_chat_id": "", "webhook_url": "", "panel_url": "",
}
NUMERIC = {"disk_warn", "disk_crit", "cpu_warn", "mem_warn", "offline_seconds",
           "device_offline_seconds", "scan_ports", "brute_fails", "check_fail_count", "cert_warn_days",
           "usb_alert", "dlp_delete_threshold", "dlp_read_threshold", "dlp_retention_days", "reminder_minutes", "notify_warn"}


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()
    return salt + "$" + digest


def check_password(password, stored):
    try:
        salt, _ = stored.split("$", 1)
    except (ValueError, AttributeError):
        return False
    return secrets.compare_digest(hash_password(password, salt), stored)


class DB:
    def __init__(self, path):
        self.path = path
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self._migrate()

    def _migrate(self):
        """Şemayı kurar ve eski (tek yönetici parolalı) veritabanlarını kullanıcı tablosuna taşır."""
        c = self.conn()
        columns = lambda table: {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
        if columns("sessions") and "user_id" not in columns("sessions"):
            c.execute("DROP TABLE sessions")  # eski oturumlar kullanıcıya bağlı değil; yeniden giriş gerekir
        c.executescript(SCHEMA)
        if "acked_by" not in columns("alerts"):
            c.execute("ALTER TABLE alerts ADD COLUMN acked_by TEXT")
        legacy = c.execute("SELECT value FROM settings WHERE key='admin_hash'").fetchone()
        if legacy:
            if not c.execute("SELECT 1 FROM users").fetchone():
                c.execute("INSERT INTO users(username,password_hash,role,all_companies,created_at) "
                          "VALUES('admin',?,'admin',1,?)", (legacy[0], time.time()))
            c.execute("DELETE FROM settings WHERE key='admin_hash'")

    def conn(self):
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            self._local.c = c
        return c

    @contextlib.contextmanager
    def tx(self):
        """Tek yazar: tüm yazmalar bu kilit altında tek işlemde yapılır."""
        with self._write_lock:
            c = self.conn()
            c.execute("BEGIN IMMEDIATE")
            try:
                yield c
            except BaseException:
                c.execute("ROLLBACK")
                raise
            else:
                c.execute("COMMIT")

    def q(self, sql, args=()):
        return [dict(r) for r in self.conn().execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        r = self.conn().execute(sql, args).fetchone()
        return dict(r) if r else None

    def write(self, sql, args=()):
        with self.tx() as c:
            return c.execute(sql, args)

    # --- ayarlar ---
    def settings(self):
        out = dict(DEFAULTS)
        for r in self.q("SELECT key, value FROM settings"):
            out[r["key"]] = r["value"]
        return out

    def get(self, key, default=""):
        r = self.one("SELECT value FROM settings WHERE key=?", (key,))
        return r["value"] if r else DEFAULTS.get(key, default)

    def set(self, key, value):
        self.write("INSERT INTO settings(key,value) VALUES(?,?) "
                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    def num(self, key):
        try:
            return float(self.get(key))
        except ValueError:
            return float(DEFAULTS[key])

    # --- kullanıcılar ---
    def create_user(self, username, password, role, company_ids=None):
        """company_ids None ise kullanıcı tüm şirketleri görür."""
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO users(username,password_hash,role,all_companies,created_at) VALUES(?,?,?,?,?)",
                (username, hash_password(password), role, 1 if company_ids is None else 0, time.time()))
            for cid in company_ids or []:
                c.execute("INSERT OR IGNORE INTO user_companies(user_id,company_id) VALUES(?,?)",
                          (cur.lastrowid, cid))
            return cur.lastrowid

    def set_user_companies(self, user_id, company_ids):
        with self.tx() as c:
            c.execute("UPDATE users SET all_companies=? WHERE id=?", (1 if company_ids is None else 0, user_id))
            c.execute("DELETE FROM user_companies WHERE user_id=?", (user_id,))
            for cid in company_ids or []:
                c.execute("INSERT OR IGNORE INTO user_companies(user_id,company_id) VALUES(?,?)", (user_id, cid))

    def user_company_ids(self, user_id):
        return [r["company_id"] for r in
                self.q("SELECT company_id FROM user_companies WHERE user_id=? ORDER BY company_id", (user_id,))]

    # --- şirketler ---
    def create_company(self, code, name):
        token = "nbt_" + secrets.token_urlsafe(32)
        cur = self.write(
            "INSERT INTO companies(code,name,token_hash,token_hint,created_at) VALUES(?,?,?,?,?)",
            (code, name, sha256(token), token[-4:], time.time()))
        return cur.lastrowid, token

    def rotate_token(self, company_id):
        token = "nbt_" + secrets.token_urlsafe(32)
        self.write("UPDATE companies SET token_hash=?, token_hint=? WHERE id=?",
                   (sha256(token), token[-4:], company_id))
        return token

    def company_by_token(self, token):
        return self.one("SELECT * FROM companies WHERE token_hash=?", (sha256(token),))

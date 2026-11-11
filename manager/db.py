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
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, created_at REAL, expires_at REAL);
"""

# Panelden değiştirilebilen ayarlar ve varsayılanları.
DEFAULTS = {
    "disk_warn": "80", "disk_crit": "90", "cpu_warn": "90", "mem_warn": "90",
    "offline_seconds": "120", "device_offline_seconds": "600",
    "scan_ports": "15", "brute_fails": "10",
    "reminder_minutes": "15", "notify_warn": "0",
    "telegram_bot_token": "", "telegram_chat_id": "", "webhook_url": "", "panel_url": "",
}
NUMERIC = {"disk_warn", "disk_crit", "cpu_warn", "mem_warn", "offline_seconds",
           "device_offline_seconds", "scan_ports", "brute_fails", "reminder_minutes", "notify_warn"}


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
        self.conn().executescript(SCHEMA)

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

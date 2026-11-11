"""Ajan raporlarının işlenmesi, uyarı kuralları ve periyodik bakım."""
import html
import ipaddress
import json
import time

SEV_LABEL = {"crit": "KRİTİK", "warn": "UYARI", "info": "BİLGİ"}
SEV_ICON = {"crit": "\U0001F534", "warn": "\U0001F7E0", "info": "\U0001F535"}
METRIC_RETENTION = 7 * 86400
EVENT_RETENTION = 30 * 86400
MAX_CONNECTIONS = 5000
MAX_DEVICES = 2048


# --- girdi temizleme: ajan verisi güvenilmez kabul edilir ---
def _s(value, limit=128):
    text = "" if value is None else str(value)
    return "".join(ch for ch in text if ch.isprintable())[:limit]


def _f(value, lo=0.0, hi=float("inf")):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number:  # NaN
        return None
    return max(lo, min(hi, number))


def _i(value, lo=0, hi=2**53):
    number = _f(value, lo, hi)
    return None if number is None else int(number)


def _port(value):
    number = _f(value)
    return int(number) if number is not None and 1 <= number <= 65535 and number == int(number) else None


def _ip(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def _mac(value):
    text = str(value or "").lower()
    parts = text.split(":")
    if len(parts) == 6 and all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts):
        return text
    return None


def fmt_time(ts):
    return time.strftime("%d.%m.%Y %H:%M", time.localtime(ts))


class Engine:
    def __init__(self, db, notifier):
        self.db = db
        self.notifier = notifier

    # ------------------------------------------------------------------ uyarılar
    def _notify(self, c, alert_id, resolved=False, reminder=False):
        """Bildirimi kuyruğa koyar. Çağıran işlem (tx) içinde olmalıdır."""
        row = c.execute(
            "SELECT a.*, co.name company, co.code, co.telegram_chat_id chat, h.hostname, h.ip "
            "FROM alerts a JOIN companies co ON co.id=a.company_id "
            "LEFT JOIN hosts h ON h.id=a.host_id WHERE a.id=?", (alert_id,)).fetchone()
        if row is None:
            return
        if resolved:
            head = "✅ ÇÖZÜLDÜ"
        else:
            head = f"{SEV_ICON[row['severity']]} {SEV_LABEL[row['severity']]}"
            if reminder:
                head += " (onay bekliyor)"
        lines = [f"<b>{head} — {html.escape(row['company'])} ({html.escape(row['code'])})</b>",
                 html.escape(row["title"])]
        if row["detail"]:
            lines.append(html.escape(row["detail"]))
        if row["hostname"]:
            lines.append(f"Sunucu: {html.escape(row['hostname'])} ({html.escape(row['ip'] or '-')})")
        lines.append("Başlangıç: " + fmt_time(row["started_at"]))
        panel = self.db.get("panel_url")
        if panel:
            lines.append(html.escape(panel.rstrip("/") + "/#/alerts"))
        self.notifier.send({
            "chat_id": row["chat"], "text": "\n".join(lines),
            "event": {"alert_id": row["id"], "company": row["code"], "severity": row["severity"],
                      "title": row["title"], "host": row["hostname"], "resolved": resolved}})
        c.execute("UPDATE alerts SET notified_at=? WHERE id=?", (time.time(), alert_id))

    def _should_notify(self, severity):
        return severity == "crit" or (severity == "warn" and self.db.num("notify_warn") >= 1)

    def raise_alert(self, c, company_id, host_id, key, severity, title, detail, now, expire_after=None):
        row = c.execute(
            "SELECT id, severity FROM alerts WHERE company_id=? AND host_id IS ? AND key=? "
            "AND resolved_at IS NULL", (company_id, host_id, key)).fetchone()
        if row:
            c.execute("UPDATE alerts SET last_seen=?, severity=?, title=?, detail=? WHERE id=?",
                      (now, severity, title, detail, row["id"]))
            if severity == "crit" and row["severity"] != "crit":
                self._notify(c, row["id"])  # uyarıdan kritiğe yükseldi
            return row["id"]
        cur = c.execute(
            "INSERT INTO alerts(company_id,host_id,key,severity,title,detail,started_at,last_seen,expire_after) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (company_id, host_id, key, severity, title, detail, now, now, expire_after))
        if self._should_notify(severity):
            self._notify(c, cur.lastrowid)
        return cur.lastrowid

    def clear_alert(self, c, company_id, host_id, key, now):
        rows = c.execute(
            "SELECT id, notified_at FROM alerts WHERE company_id=? AND host_id IS ? AND key=? "
            "AND resolved_at IS NULL", (company_id, host_id, key)).fetchall()
        for row in rows:
            c.execute("UPDATE alerts SET resolved_at=? WHERE id=?", (now, row["id"]))
            if row["notified_at"]:
                self._notify(c, row["id"], resolved=True)

    # ------------------------------------------------------------------ rapor işleme
    def ingest(self, company, payload, now=None):
        now = now or time.time()
        if not isinstance(payload, dict):
            raise ValueError("geçersiz rapor")
        host = payload.get("host") if isinstance(payload.get("host"), dict) else {}
        agent_id = _s(host.get("id") or host.get("hostname"), 64)
        if not agent_id:
            raise ValueError("host.id gerekli")
        m = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
        cid = company["id"]

        disks = []
        for d in (m.get("disks") or [])[:32]:
            if isinstance(d, dict) and _f(d.get("pct"), 0, 100) is not None:
                disks.append({"mount": _s(d.get("mount"), 128), "pct": round(_f(d.get("pct"), 0, 100), 1),
                              "total": _i(d.get("total")) or 0, "used": _i(d.get("used")) or 0})
        listening = sorted({p for p in (_port(x) for x in (payload.get("listening") or [])[:1024]) if p})
        subnets = [_s(x, 64) for x in (payload.get("subnets") or [])[:16]]
        cpu, mem = _f(m.get("cpu"), 0, 100), _f(m.get("mem_pct"), 0, 100)
        disk_max = max((d["pct"] for d in disks), default=None)
        cfg = {k: self.db.num(k) for k in
               ("disk_warn", "disk_crit", "cpu_warn", "mem_warn", "scan_ports", "brute_fails",
                "device_offline_seconds")}

        with self.db.tx() as c:
            c.execute(
                "INSERT INTO hosts(company_id,agent_id,first_seen) VALUES(?,?,?) "
                "ON CONFLICT(company_id,agent_id) DO NOTHING", (cid, agent_id, now))
            hrow = c.execute("SELECT id, last_scan FROM hosts WHERE company_id=? AND agent_id=?",
                             (cid, agent_id)).fetchone()
            hid, had_scan = hrow["id"], hrow["last_scan"] is not None
            c.execute(
                "UPDATE hosts SET hostname=?, ip=?, os=?, cores=?, agent_version=?, capture_mode=?, "
                "uptime_s=?, cpu=?, mem_pct=?, mem_used=?, mem_total=?, load1=?, rx_bps=?, tx_bps=?, "
                "disks=?, listening=?, subnets=?, last_seen=? WHERE id=?",
                (_s(host.get("hostname"), 128) or agent_id, _ip(host.get("ip")), _s(host.get("os"), 128),
                 _i(host.get("cores"), 0, 4096), _s(payload.get("agent_version"), 32),
                 _s(payload.get("capture_mode"), 16), _f(host.get("uptime_s")), cpu, mem,
                 _i(m.get("mem_used")), _i(m.get("mem_total")), _f(m.get("load1")),
                 _f(m.get("rx_bps")), _f(m.get("tx_bps")), json.dumps(disks), json.dumps(listening),
                 json.dumps(subnets), now, hid))
            c.execute("INSERT INTO metrics(host_id,ts,cpu,mem_pct,disk_pct,rx_bps,tx_bps) VALUES(?,?,?,?,?,?,?)",
                      (hid, now, cpu, mem, disk_max, _f(m.get("rx_bps")), _f(m.get("tx_bps"))))

            self.clear_alert(c, cid, hid, "offline", now)
            self._check_resources(c, cid, hid, disks, mem, cfg, now)
            self._ingest_connections(c, cid, hid, payload, listening, cfg, now)
            if isinstance(payload.get("devices"), list):
                self._ingest_devices(c, cid, hid, payload["devices"], had_scan, cfg, now)
        return hid

    def _check_resources(self, c, cid, hid, disks, mem, cfg, now):
        seen = set()
        for d in disks:
            key = "disk:" + d["mount"]
            seen.add(key)
            if d["pct"] >= cfg["disk_warn"]:
                sev = "crit" if d["pct"] >= cfg["disk_crit"] else "warn"
                self.raise_alert(c, cid, hid, key, sev, f"Disk doluluğu %{d['pct']:.0f} ({d['mount']})",
                                 f"Eşik: uyarı %{cfg['disk_warn']:.0f}, kritik %{cfg['disk_crit']:.0f}", now)
            else:
                self.clear_alert(c, cid, hid, key, now)
        # Artık raporlanmayan bölümlerin uyarıları açık kalmasın.
        for row in c.execute("SELECT key FROM alerts WHERE host_id=? AND resolved_at IS NULL "
                             "AND key LIKE 'disk:%'", (hid,)).fetchall():
            if row["key"] not in seen:
                self.clear_alert(c, cid, hid, row["key"], now)

        recent = c.execute("SELECT cpu FROM metrics WHERE host_id=? ORDER BY ts DESC LIMIT 5", (hid,)).fetchall()
        cpus = [r["cpu"] for r in recent if r["cpu"] is not None]
        if len(cpus) == 5 and sum(cpus) / 5 >= cfg["cpu_warn"]:
            self.raise_alert(c, cid, hid, "cpu", "warn", f"CPU kullanımı sürekli yüksek (%{sum(cpus) / 5:.0f})",
                             "Son 5 ölçümün ortalaması eşiğin üzerinde", now)
        elif cpus and cpus[0] < cfg["cpu_warn"]:
            self.clear_alert(c, cid, hid, "cpu", now)
        if mem is not None and mem >= cfg["mem_warn"]:
            self.raise_alert(c, cid, hid, "mem", "warn", f"Bellek kullanımı %{mem:.0f}", "", now)
        elif mem is not None:
            self.clear_alert(c, cid, hid, "mem", now)

    def _ingest_connections(self, c, cid, hid, payload, listening, cfg, now):
        sources = set()
        for e in (payload.get("connections") or [])[:MAX_CONNECTIONS]:
            if not isinstance(e, dict):
                continue
            src, port, count = _ip(e.get("src")), _port(e.get("port")), _i(e.get("count"), 1, 10**9)
            if not (src and port and count):
                continue
            is_open = 1 if (e.get("open") if "open" in e else port in listening) else 0
            c.execute("INSERT INTO conn_events(company_id,host_id,ts,kind,src,port,open,count) "
                      "VALUES(?,?,?,'tcp',?,?,?,?)", (cid, hid, now, src, port, is_open, count))
            sources.add(src)
        fail_sources = set()
        for e in (payload.get("auth") or [])[:MAX_CONNECTIONS]:
            if not isinstance(e, dict):
                continue
            src, count = _ip(e.get("src")), _i(e.get("count"), 1, 10**9)
            if not (src and count):
                continue
            kind = "ssh_ok" if e.get("result") == "ok" else "ssh_fail"
            c.execute("INSERT INTO conn_events(company_id,host_id,ts,kind,src,port,user,open,count) "
                      "VALUES(?,?,?,?,?,22,?,1,?)", (cid, hid, now, kind, src, _s(e.get("user"), 64), count))
            if kind == "ssh_fail":
                fail_sources.add(src)

        since = now - 600
        for src in sources:
            row = c.execute(
                "SELECT COUNT(DISTINCT port) ports, COUNT(DISTINCT CASE WHEN open=0 THEN port END) closed "
                "FROM conn_events WHERE host_id=? AND kind='tcp' AND src=? AND ts>=?", (hid, src, since)).fetchone()
            if row["ports"] >= cfg["scan_ports"]:
                self.raise_alert(c, cid, hid, "scan:" + src, "crit", f"Port taraması: {src}",
                                 f"Son 10 dakikada {row['ports']} farklı port denendi ({row['closed']} kapalı port)",
                                 now, expire_after=1800)
        for src in fail_sources:
            row = c.execute(
                "SELECT COALESCE(SUM(count),0) n, COUNT(DISTINCT user) users FROM conn_events "
                "WHERE host_id=? AND kind='ssh_fail' AND src=? AND ts>=?", (hid, src, since)).fetchone()
            if row["n"] >= cfg["brute_fails"]:
                self.raise_alert(c, cid, hid, "brute:" + src, "crit", f"SSH parola denemesi saldırısı: {src}",
                                 f"Son 10 dakikada {row['n']} başarısız giriş, {row['users']} farklı kullanıcı adı",
                                 now, expire_after=1800)

    def _ingest_devices(self, c, cid, hid, devices, had_scan, cfg, now):
        for d in devices[:MAX_DEVICES]:
            if not isinstance(d, dict):
                continue
            ip, mac = _ip(d.get("ip")), _mac(d.get("mac"))
            if not (ip and mac):
                continue
            known = c.execute("SELECT id FROM devices WHERE company_id=? AND mac=?", (cid, mac)).fetchone()
            name, iface, gw = _s(d.get("hostname"), 128), _s(d.get("iface"), 32), 1 if d.get("gateway") else 0
            if known:
                c.execute("UPDATE devices SET ip=?, host_id=?, iface=?, is_gateway=?, last_seen=?, "
                          "hostname=CASE WHEN ?<>'' THEN ? ELSE hostname END WHERE id=?",
                          (ip, hid, iface, gw, now, name, name, known["id"]))
            else:
                c.execute("INSERT INTO devices(company_id,host_id,ip,mac,hostname,iface,is_gateway,first_seen,last_seen) "
                          "VALUES(?,?,?,?,?,?,?,?,?)", (cid, hid, ip, mac, name, iface, gw, now, now))
                if had_scan:  # ilk tarama taban çizgisidir, uyarı üretmez
                    self.raise_alert(c, cid, hid, "newdev:" + mac, "info", f"Ağda yeni cihaz: {ip}",
                                     f"MAC {mac}" + (f" · {name}" if name else ""), now, expire_after=86400)
        c.execute("UPDATE hosts SET last_scan=? WHERE id=?", (now, hid))
        for d in c.execute("SELECT * FROM devices WHERE company_id=? AND host_id=? AND watched=1",
                           (cid, hid)).fetchall():
            key = "device:" + d["mac"]
            if d["last_seen"] < now - cfg["device_offline_seconds"]:
                label = d["label"] or d["hostname"] or d["ip"]
                self.raise_alert(c, cid, hid, key, "crit", f"İzlenen cihaz yanıt vermiyor: {label}",
                                 f"{d['ip']} · MAC {d['mac']} · son görülme {fmt_time(d['last_seen'])}", now)
            else:
                self.clear_alert(c, cid, hid, key, now)

    # ------------------------------------------------------------------ periyodik bakım
    def tick(self, now=None):
        now = now or time.time()
        offline_after = self.db.num("offline_seconds")
        reminder = self.db.num("reminder_minutes") * 60
        with self.db.tx() as c:
            for h in c.execute("SELECT id, company_id, hostname, last_seen FROM hosts").fetchall():
                if h["last_seen"] and h["last_seen"] < now - offline_after:
                    self.raise_alert(c, h["company_id"], h["id"], "offline", "crit",
                                     f"Sunucu yanıt vermiyor: {h['hostname']}",
                                     f"Son rapor: {fmt_time(h['last_seen'])}", now)
            # Olay tabanlı uyarılar (tarama, yeni cihaz) tekrarlanmazsa kendiliğinden kapanır.
            for a in c.execute("SELECT id, company_id, host_id, key FROM alerts WHERE resolved_at IS NULL "
                               "AND expire_after IS NOT NULL AND last_seen < ? - expire_after", (now,)).fetchall():
                c.execute("UPDATE alerts SET resolved_at=? WHERE id=?", (now, a["id"]))
            # Acil durum çağrısı: onaylanmayan kritik uyarılar için bildirim tekrarlanır.
            if reminder > 0:
                for a in c.execute("SELECT id FROM alerts WHERE resolved_at IS NULL AND acked_at IS NULL "
                                   "AND severity='crit' AND notified_at IS NOT NULL AND notified_at < ?",
                                   (now - reminder,)).fetchall():
                    self._notify(c, a["id"], reminder=True)
            c.execute("DELETE FROM metrics WHERE ts < ?", (now - METRIC_RETENTION,))
            c.execute("DELETE FROM conn_events WHERE ts < ?", (now - EVENT_RETENTION,))
            c.execute("DELETE FROM alerts WHERE resolved_at IS NOT NULL AND resolved_at < ?", (now - EVENT_RETENTION,))
            c.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))

#!/usr/bin/env python3
"""Nöbet Agent — şirket sunucusuna kurulur, Manager'a rapor gönderir.

Tek dosya, yalnızca Python 3.8+ standart kitaplığı (Linux). Topladıkları:
  * sunucu kaynakları (CPU, bellek, disk, ağ trafiği)
  * yerel ağdaki tüm cihazlar (ARP tabanlı keşif)
  * sunucuya gelen bağlantı denemeleri (TCP SYN yakalama; kapalı portlara gelenler dahil)
  * SSH giriş denemeleri (başarılı/başarısız)
  * Manager'da tanımlanan servis sağlık kontrolleri (TCP portu, HTTP/HTTPS adresi, sertifika süresi)
  * veri sızıntısı izleme: USB depolama takılması ve Manager'da tanımlanan hassas klasörlerdeki
    dosya işlemleri (inotify; Linux'ta işlemi yapan kullanıcı bilinmez)

Kullanım:  nobet_agent.py --config /etc/nobet/agent.json
           nobet_agent.py --manager https://panel.example.com --token nbt_... [--once --print]
"""
import argparse
import concurrent.futures
import ctypes
import ctypes.util
import http.client
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import select
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.1.0"
REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "vfat", "ntfs", "ntfs3", "f2fs", "reiserfs", "jfs"}
VIRTUAL_IFACE = ("lo", "docker", "veth", "br-", "virbr", "cni", "flannel", "tun", "tap", "wg")
MAX_PENDING = 20000

FAILED_RE = re.compile(r"Failed \S+ for (?:invalid user )?(\S+) from (\S+)")
ACCEPTED_RE = re.compile(r"Accepted \S+ for (\S+) from (\S+)")


# ----------------------------------------------------------------------------- sistem ölçümleri
def read_cpu_times(text=None):
    """/proc/stat ilk satırından (boşta, toplam) döndürür."""
    if text is None:
        with open("/proc/stat") as f:
            text = f.readline()
    values = [int(x) for x in text.split()[1:9]]
    return values[3] + values[4], sum(values)


def read_meminfo(text=None):
    if text is None:
        with open("/proc/meminfo") as f:
            text = f.read()
    info = {}
    for line in text.splitlines():
        name, _, rest = line.partition(":")
        if rest:
            info[name] = int(rest.split()[0]) * 1024
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", info.get("MemFree", 0))
    used = total - available
    return {"mem_total": total, "mem_used": used, "mem_pct": round(used * 100 / total, 1) if total else 0}


def read_net_bytes(text=None):
    if text is None:
        with open("/proc/net/dev") as f:
            text = f.read()
    rx = tx = 0
    for line in text.splitlines()[2:]:
        name, _, rest = line.partition(":")
        if name.strip().startswith(VIRTUAL_IFACE):
            continue
        cols = rest.split()
        if len(cols) >= 9:
            rx += int(cols[0])
            tx += int(cols[8])
    return rx, tx


def read_disks():
    disks, seen = [], set()
    try:
        with open("/proc/mounts") as f:
            mounts = [line.split() for line in f]
    except OSError:
        mounts = []
    for parts in mounts:
        if len(parts) < 3:
            continue
        device, mount, fstype = parts[0], parts[1].replace("\\040", " "), parts[2]
        if not (fstype in REAL_FS or (fstype == "overlay" and mount == "/")) or device in seen:
            continue
        seen.add(device)
        try:
            usage = shutil.disk_usage(mount)
        except OSError:
            continue
        if usage.total:
            disks.append({"mount": mount, "total": usage.total, "used": usage.used,
                          "pct": round(usage.used * 100 / usage.total, 1)})
    return disks


def _hex_ip(text):
    """/proc/net/tcp adres biçimini (ana makine bayt sıralı onaltılık) IP dizesine çevirir."""
    if len(text) == 8:
        return socket.inet_ntoa(struct.pack("=I", int(text, 16)))
    raw = b"".join(struct.pack("=I", int(text[i:i + 8], 16)) for i in range(0, 32, 8))
    addr = ipaddress.IPv6Address(raw)
    return str(addr.ipv4_mapped or addr)


def read_tcp_table(texts=None):
    """(dinlenen portlar, kurulu bağlantılar [(uzak ip, uzak port, yerel port)]) döndürür."""
    if texts is None:
        texts = []
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(path) as f:
                    texts.append(f.read())
            except OSError:
                pass
    listening, established = set(), []
    for text in texts:
        for line in text.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 4:
                continue
            local, remote, state = cols[1], cols[2], cols[3]
            lport = int(local.rsplit(":", 1)[1], 16)
            if state == "0A":
                listening.add(lport)
            elif state == "01":
                rip, rport = remote.rsplit(":", 1)
                established.append((_hex_ip(rip), int(rport, 16), lport))
    return listening, established


# ----------------------------------------------------------------------------- ağ bilgisi ve keşif
def local_networks(override=None):
    """(yerel IP kümesi, taranacak alt ağlar) döndürür."""
    ips, nets = set(), []
    try:
        out = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=5).stdout
        for iface in json.loads(out or "[]"):
            name = iface.get("ifname", "")
            for addr in iface.get("addr_info", []):
                if addr.get("family") != "inet":
                    continue
                ips.add(addr["local"])
                if name.startswith(VIRTUAL_IFACE) or addr.get("scope") != "global":
                    continue
                # Çok büyük alt ağlarda yalnızca sunucunun /24 dilimi taranır.
                prefix = max(int(addr.get("prefixlen", 24)), 22)
                nets.append(ipaddress.ip_network(f"{addr['local']}/{prefix}", strict=False))
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    if not ips:  # iproute2 yoksa: çekirdeğin yerel adres tablosu + birincil adresin /24 dilimi
        ips |= fib_local_ips()
        primary = primary_ip()
        if primary:
            ips.add(primary)
            nets.append(ipaddress.ip_network(primary + "/24", strict=False))
    if override:
        nets = [ipaddress.ip_network(n, strict=False) for n in override]
    return ips, sorted(set(nets), key=str)


def fib_local_ips(text=None):
    """/proc/net/fib_trie içindeki LOCAL kayıtlarından sunucunun kendi IPv4 adreslerini çıkarır."""
    try:
        if text is None:
            with open("/proc/net/fib_trie") as f:
                text = f.read()
    except OSError:
        return set()
    found, previous = set(), ""
    for line in text.splitlines():
        if "/32 host LOCAL" in line:
            candidate = previous.split()[-1] if previous.split() else ""
            try:
                found.add(str(ipaddress.IPv4Address(candidate)))
            except ValueError:
                pass
        previous = line
    return found


def primary_ip(target="192.0.2.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def default_gateway(text=None):
    try:
        if text is None:
            with open("/proc/net/route") as f:
                text = f.read()
    except OSError:
        return None
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 3 and cols[1] == "00000000":
            return socket.inet_ntoa(struct.pack("=I", int(cols[2], 16)))
    return None


def parse_arp(text):
    """/proc/net/arp içeriğinden tamamlanmış kayıtları [(ip, mac, arayüz)] döndürür."""
    entries = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 6 and int(cols[2], 16) & 0x2 and cols[3] != "00:00:00:00:00:00":
            entries.append((cols[0], cols[3].lower(), cols[5]))
    return entries


class Discovery:
    """Alt ağdaki her adrese boş bir UDP paketi yollayıp çekirdeğin ARP çözümlemesini tetikler,
    ardından ARP tablosunu okur. Ping ikilisi veya root yetkisi gerektirmez."""

    def __init__(self):
        self.names = {}

    def scan(self, nets):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sent = 0
        for net in nets:
            for ip in net.hosts():
                try:
                    sock.sendto(b"", (str(ip), 9))
                except OSError:
                    pass
                sent += 1
                if sent % 64 == 0:
                    time.sleep(0.05)
        sock.close()
        time.sleep(2)
        try:
            with open("/proc/net/arp") as f:
                entries = parse_arp(f.read())
        except OSError:
            entries = []
        gateway = default_gateway()
        wanted = [(ip, mac, dev) for ip, mac, dev in entries
                  if any(ipaddress.ip_address(ip) in net for net in nets)]
        self._resolve([ip for ip, _, _ in wanted if ip not in self.names])
        return [{"ip": ip, "mac": mac, "iface": dev, "hostname": self.names.get(ip, ""),
                 "gateway": ip == gateway} for ip, mac, dev in wanted]

    def _resolve(self, ips):
        def lookup(ip):
            try:
                return ip, socket.gethostbyaddr(ip)[0]
            except OSError:
                return ip, ""
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=16)
        futures = [pool.submit(lookup, ip) for ip in ips[:512]]
        done, _ = concurrent.futures.wait(futures, timeout=8)
        for fut in done:
            ip, name = fut.result()
            self.names[ip] = name
        pool.shutdown(wait=False)


# ----------------------------------------------------------------------------- bağlantı yakalama
def parse_syn(frame):
    """Ethernet çerçevesi yeni bir TCP bağlantı isteğiyse (SYN, ACK yok) (kaynak, hedef, hedef port)."""
    if len(frame) < 54:
        return None
    offset = 14
    ethertype = frame[12:14]
    if ethertype == b"\x81\x00":  # VLAN etiketi
        ethertype, offset = frame[16:18], 18
    if ethertype != b"\x08\x00":
        return None
    ihl = (frame[offset] & 0x0F) * 4
    if frame[offset] >> 4 != 4 or frame[offset + 9] != 6:
        return None
    if struct.unpack("!H", frame[offset + 6:offset + 8])[0] & 0x1FFF:  # parçalı paketin devamı
        return None
    tcp = offset + ihl
    if len(frame) < tcp + 14:
        return None
    flags = frame[tcp + 13]
    if not flags & 0x02 or flags & 0x10:
        return None
    return (socket.inet_ntoa(frame[offset + 12:offset + 16]),
            socket.inet_ntoa(frame[offset + 16:offset + 20]),
            struct.unpack("!H", frame[tcp + 2:tcp + 4])[0])


class ConnectionMonitor:
    """Sunucuya gelen bağlantı denemelerini (kaynak IP, hedef port) bazında sayar.

    Mümkünse ham soketle SYN paketlerini dinler ("sniffer": kapalı portlara gelenleri de görür).
    Yetki yoksa kurulu bağlantı tablosunu yoklar ("poll": yalnızca kabul edilen bağlantılar)."""

    def __init__(self, local_ips):
        self.local_ips = set(local_ips)
        self.counts = {}
        self.lock = threading.Lock()
        self.mode = "poll"
        self._seen = set()
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            self.mode = "sniffer"
        except (OSError, AttributeError):
            self.sock = None
            self._seen = set(read_tcp_table()[1])  # mevcut bağlantılar yeni sayılmasın
        threading.Thread(target=self._sniff if self.sock else self._poll, daemon=True).start()

    def record(self, src, port, n=1):
        if src in self.local_ips or src.startswith("127."):
            return
        with self.lock:
            if (src, port) in self.counts or len(self.counts) < MAX_PENDING:
                self.counts[(src, port)] = self.counts.get((src, port), 0) + n

    def _sniff(self):
        while True:
            try:
                frame, addr = self.sock.recvfrom(65535)
            except OSError:
                time.sleep(1)
                continue
            # addr = (arayüz, protokol, paket türü, donanım türü, adres); 4 = giden paket
            if addr[2] == 4 or addr[3] not in (1, 772):
                continue
            syn = parse_syn(frame)
            if syn and syn[1] in self.local_ips:
                self.record(syn[0], syn[2])

    def _poll(self):
        while True:
            time.sleep(2)
            try:
                listening, established = read_tcp_table()
            except (OSError, ValueError):
                continue
            current = set(established)
            for rip, rport, lport in current - self._seen:
                if lport in listening:
                    self.record(rip, lport)
            self._seen = current

    def drain(self):
        with self.lock:
            counts, self.counts = self.counts, {}
        return counts

    def restore(self, counts):
        for (src, port), n in counts.items():
            self.record(src, port, n)


def parse_auth_lines(lines):
    """sshd günlük satırlarından {(kaynak, kullanıcı, sonuç): adet} üretir."""
    counts = {}
    for line in lines:
        m = FAILED_RE.search(line)
        result = "fail"
        if not m:
            m, result = ACCEPTED_RE.search(line), "ok"
        if m:
            key = (m.group(2), m.group(1)[:64], result)
            counts[key] = counts.get(key, 0) + 1
    return counts


class AuthLog:
    """SSH giriş denemelerini auth günlüğünden (yoksa journald'den) artımlı okur."""
    FILES = ("/var/log/auth.log", "/var/log/secure")

    def __init__(self):
        self.path = next((p for p in self.FILES if os.path.isfile(p) and os.access(p, os.R_OK)), None)
        self.inode = self.pos = None
        self.since = time.time()
        self.journal = self.path is None and shutil.which("journalctl") is not None
        if self.path:
            st = os.stat(self.path)
            self.inode, self.pos = st.st_ino, st.st_size  # geçmişi yeniden sayma

    def read(self):
        if self.path:
            return parse_auth_lines(self._read_file())
        if self.journal:
            since, self.since = self.since, time.time()
            try:
                out = subprocess.run(
                    ["journalctl", "-q", "-o", "cat", "--no-pager", f"--since=@{int(since)}",
                     "-t", "sshd", "-t", "sshd-session"],
                    capture_output=True, text=True, timeout=10).stdout
            except (OSError, subprocess.SubprocessError):
                return {}
            return parse_auth_lines(out.splitlines())
        return {}

    def _read_file(self):
        try:
            st = os.stat(self.path)
            if st.st_ino != self.inode or st.st_size < self.pos:  # günlük döndürülmüş
                self.inode, self.pos = st.st_ino, 0
            with open(self.path, errors="replace") as f:
                f.seek(self.pos)
                data = f.read(4 * 1024 * 1024)
                self.pos = f.tell()
            return data.splitlines()
        except OSError:
            return []


# ----------------------------------------------------------------------------- veri sızıntısı izleme
def scan_usb_storage(sys_block="/sys/block"):
    """Takılı USB depolama aygıtlarını {anahtar: bilgi} olarak döndürür (sysfs üzerinden)."""
    def read(path):
        try:
            with open(path) as f:
                return f.read().strip()
        except OSError:
            return ""
    found = {}
    try:
        names = os.listdir(sys_block)
    except OSError:
        return found
    for name in names:
        device = os.path.join(sys_block, name, "device")
        real = os.path.realpath(device)
        if "/usb" not in real:
            continue
        try:
            size = int(read(os.path.join(sys_block, name, "size")) or 0) * 512
        except ValueError:
            size = 0
        info = {"vendor": read(os.path.join(device, "vendor")), "model": read(os.path.join(device, "model")),
                "size": size, "serial": ""}
        parent = real
        for _ in range(8):   # seri numarası USB aygıt düğümünde, birkaç seviye yukarıda durur
            if os.path.isfile(os.path.join(parent, "serial")):
                info["serial"] = read(os.path.join(parent, "serial"))
                break
            parent = os.path.dirname(parent)
        found[info["serial"] or name] = info
    return found


class UsbMonitor:
    """USB depolama takılma/çıkarılma olaylarını yakalar. Başlangıçta takılı olanlar olay sayılmaz."""

    def __init__(self, sys_block="/sys/block", interval=3):
        self.sys_block = sys_block
        self.known = scan_usb_storage(sys_block)
        self.events = []
        self.lock = threading.Lock()
        if interval:
            threading.Thread(target=self._loop, args=(interval,), daemon=True).start()

    def _loop(self, interval):
        while True:
            time.sleep(interval)
            self.poll()

    def poll(self):
        current = scan_usb_storage(self.sys_block)
        with self.lock:
            for key, info in current.items():
                if key not in self.known:
                    self.events.append(dict(info, action="insert"))
            for key, info in self.known.items():
                if key not in current:
                    self.events.append(dict(info, action="remove"))
            self.known = current
            del self.events[:-200]

    def drain(self):
        with self.lock:
            events, self.events = self.events, []
        return events

    def restore(self, events):
        with self.lock:
            self.events = events + self.events


IN_CLOSE_WRITE, IN_CLOSE_NOWRITE, IN_MOVED_FROM, IN_MOVED_TO = 0x8, 0x10, 0x40, 0x80
IN_CREATE, IN_DELETE, IN_Q_OVERFLOW, IN_IGNORED, IN_ISDIR = 0x100, 0x200, 0x4000, 0x8000, 0x40000000
IN_ONLYDIR, IN_DONT_FOLLOW = 0x01000000, 0x02000000
WATCH_MASK = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE
FORBIDDEN_ROOTS = ("/", "/proc", "/sys", "/dev", "/run", "/etc", "/bin", "/sbin", "/usr", "/lib", "/boot")


class FolderWatcher:
    """Hassas klasörlerdeki dosya işlemlerini inotify ile izler (alt klasörler dahil).

    Yalnızca dosya adı ve işlem türü kaydedilir; dosya içeriği okunmaz. inotify işlemi yapan
    kullanıcıyı bildirmediği için Linux'ta kullanıcı alanı boş kalır."""
    MAX_DIRS = 8192

    def __init__(self, watches):
        self.counts, self.lock = {}, threading.Lock()
        self.dirs, self.status, self.total_dirs, self.overflow = {}, {}, 0, False
        self.libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        self.fd = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        self.closed = self.fd < 0
        for w in watches:
            self.status[w["id"]] = self._add_root(w["id"], str(w.get("path", "")))
        if not self.closed:
            threading.Thread(target=self._run, daemon=True).start()

    def _add_root(self, watch_id, root):
        root = os.path.normpath(root)
        if self.closed:
            return {"id": watch_id, "ok": False, "detail": "inotify kullanılamıyor"}
        if not os.path.isabs(root) or root in FORBIDDEN_ROOTS:
            return {"id": watch_id, "ok": False, "detail": "Bu klasör izlenemez"}
        if not os.path.isdir(root):
            return {"id": watch_id, "ok": False, "detail": "Klasör bulunamadı"}
        added = self._add_tree(watch_id, root)
        if not added:
            return {"id": watch_id, "ok": False, "detail": "Klasör izlenemedi (izin veya sınır)"}
        full = self.total_dirs >= self.MAX_DIRS
        return {"id": watch_id, "ok": True,
                "detail": f"{added} klasör izleniyor" + (" (sınıra ulaşıldı, bir kısmı izlenmiyor)" if full else "")}

    def _add_tree(self, watch_id, root):
        added = 0
        for path, subdirs, _ in os.walk(root, followlinks=False):
            if self.total_dirs >= self.MAX_DIRS:
                break
            wd = self.libc.inotify_add_watch(self.fd, os.fsencode(path), WATCH_MASK | IN_ONLYDIR | IN_DONT_FOLLOW)
            if wd < 0:
                subdirs[:] = []
                continue
            if wd not in self.dirs:
                self.total_dirs += 1
            self.dirs[wd] = (watch_id, path)
            added += 1
        return added

    def _run(self):
        while not self.closed:
            try:
                if not select.select([self.fd], [], [], 1)[0]:
                    continue
                data = os.read(self.fd, 65536)
            except (OSError, ValueError):
                if self.closed:
                    return
                time.sleep(0.5)
                continue
            self.handle(data)

    def handle(self, data):
        offset = 0
        while offset + 16 <= len(data):
            wd, mask, _, length = struct.unpack_from("iIII", data, offset)
            name = data[offset + 16:offset + 16 + length].split(b"\0", 1)[0]
            offset += 16 + length
            if mask & IN_Q_OVERFLOW:
                self.overflow = True
                continue
            entry = self.dirs.get(wd)
            if mask & IN_IGNORED:
                if self.dirs.pop(wd, None):
                    self.total_dirs -= 1
                continue
            if not entry or not name:
                continue
            watch_id, directory = entry
            path = os.path.join(directory, os.fsdecode(name))
            if mask & IN_ISDIR:
                if mask & (IN_CREATE | IN_MOVED_TO):
                    self._add_tree(watch_id, path)   # yeni alt klasör de izlenir
                if mask & IN_CLOSE_NOWRITE:
                    continue                         # klasör listeleme: gürültü
            if mask & IN_CLOSE_WRITE:
                action = "write"
            elif mask & IN_CLOSE_NOWRITE:
                action = "read"
            elif mask & IN_CREATE:
                action = "create"
            elif mask & IN_DELETE:
                action = "delete"
            elif mask & (IN_MOVED_FROM | IN_MOVED_TO):
                action = "move"
            else:
                continue
            key = (watch_id, action, path)
            with self.lock:
                if key in self.counts or len(self.counts) < MAX_PENDING:
                    self.counts[key] = self.counts.get(key, 0) + 1

    def drain(self, limit=2000):
        """En fazla `limit` kayıt döndürür; kalanı sonraki rapora kalır."""
        with self.lock:
            keys = list(self.counts)[:limit]
            return {k: self.counts.pop(k) for k in keys}

    def restore(self, counts):
        with self.lock:
            for key, n in counts.items():
                self.counts[key] = self.counts.get(key, 0) + n

    def statuses(self):
        out = list(self.status.values())
        if self.overflow:
            out = [dict(st, detail=st["detail"] + " · olay kuyruğu taştı, bazı işlemler kaydedilmedi") for st in out]
        return out

    def close(self):
        self.closed = True
        try:
            os.close(self.fd)
        except OSError:
            pass


# ----------------------------------------------------------------------------- servis sağlık kontrolleri
MAX_CHECKS = 50


def run_check(check):
    """Tek bir kontrolü çalıştırır. Manager'a yalnızca durum/süre döner; yanıt gövdesi asla gönderilmez."""
    timeout = min(max(float(check.get("timeout") or 5), 1), 10)
    result = {"id": check.get("id"), "ok": False}
    started = time.monotonic()
    conn = None
    try:
        if check.get("type") == "tcp":
            host, _, port = str(check["target"]).rpartition(":")
            socket.create_connection((host, int(port)), timeout=timeout).close()
            result["ok"] = True
        elif check.get("type") == "http":
            url = urllib.parse.urlparse(str(check["target"]))
            if url.scheme == "https":
                ctx = ssl.create_default_context(cafile=check.get("_cafile"))   # _cafile yalnızca testlerde
                if not check.get("verify", True):
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=timeout, context=ctx)
            elif url.scheme == "http":
                conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=timeout)
            else:
                raise ValueError("desteklenmeyen adres")
            conn.connect()
            if url.scheme == "https":
                # Yanıt okununca soket kapanabildiği için sertifika istekten önce alınır;
                # doğrulama kapalıysa boş döner ve süre bildirilmez.
                cert = conn.sock.getpeercert()
                if cert and cert.get("notAfter"):
                    result["cert_days"] = round((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400, 1)
            path = (url.path or "/") + ("?" + url.query if url.query else "")
            conn.request("GET", path, headers={"User-Agent": "nobet-agent/" + VERSION, "Connection": "close"})
            status = conn.getresponse().status       # yönlendirmeler izlenmez
            result["status_code"] = status
            expected = check.get("expect_status")
            result["ok"] = status == expected if expected else 200 <= status < 400
            if not result["ok"]:
                result["error"] = f"HTTP {status}"
        else:
            raise ValueError("bilinmeyen kontrol türü")
    except ssl.SSLCertVerificationError as exc:
        result["error"] = "Sertifika doğrulanamadı: " + str(exc.verify_message or exc)[:120]
    except socket.timeout:
        result["error"] = "Zaman aşımı"
    except ConnectionRefusedError:
        result["error"] = "Bağlantı reddedildi"
    except socket.gaierror:
        result["error"] = "Ad çözülemedi"
    except (OSError, ValueError, KeyError, http.client.HTTPException) as exc:
        result["error"] = (str(exc) or exc.__class__.__name__)[:160]
    finally:
        if conn is not None:
            conn.close()
    result["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
    return result


def run_checks(checks):
    checks = [c for c in checks if isinstance(c, dict)][:MAX_CHECKS]
    if not checks:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(run_check, checks))


# ----------------------------------------------------------------------------- ajan döngüsü
def machine_id():
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path) as f:
                value = f.read().strip()
                if value:
                    return value
        except OSError:
            pass
    return socket.gethostname()


def os_name():
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.platform()


class Agent:
    def __init__(self, cfg):
        self.cfg = cfg
        self.local_ips, self.nets = local_networks(cfg.get("subnets"))
        self.monitor = ConnectionMonitor(self.local_ips) if cfg.get("capture", True) else None
        self.authlog = AuthLog()
        self.discovery = Discovery()
        self.prev_cpu = read_cpu_times()
        self.prev_net = read_net_bytes()
        self.prev_time = time.time()
        self.last_scan = 0
        self.pending_auth = {}
        self.checks = []   # Manager'ın son rapor yanıtında gönderdiği kontrol tanımları
        self.dlp = cfg.get("dlp", True)
        self.usb = UsbMonitor() if self.dlp else None
        self.watch_defs, self.watcher = [], None   # Manager'ın gönderdiği hassas klasörler
        self.ssl_ctx = ssl.create_default_context(cafile=cfg.get("ca_file"))
        if cfg.get("insecure"):
            print("uyarı: TLS sertifika doğrulaması kapalı (insecure)", file=sys.stderr)
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def metrics(self):
        now = time.time()
        idle, total = read_cpu_times()
        d_idle, d_total = idle - self.prev_cpu[0], total - self.prev_cpu[1]
        rx, tx = read_net_bytes()
        elapsed = max(now - self.prev_time, 0.001)
        out = {
            "cpu": round(100 * (1 - d_idle / d_total), 1) if d_total > 0 else 0.0,
            "rx_bps": round(max(rx - self.prev_net[0], 0) * 8 / elapsed),
            "tx_bps": round(max(tx - self.prev_net[1], 0) * 8 / elapsed),
            "load1": os.getloadavg()[0], "disks": read_disks(), **read_meminfo()}
        self.prev_cpu, self.prev_net, self.prev_time = (idle, total), (rx, tx), now
        return out

    def collect(self):
        listening, _ = read_tcp_table()
        with open("/proc/uptime") as f:
            uptime = float(f.read().split()[0])
        manager_host = urllib.parse.urlparse(self.cfg["manager"]).hostname or "192.0.2.1"
        try:
            ip = primary_ip(socket.gethostbyname(manager_host))
        except OSError:
            ip = primary_ip()
        conns = self.monitor.drain() if self.monitor else {}
        for key, n in self.authlog.read().items():
            self.pending_auth[key] = self.pending_auth.get(key, 0) + n
        report = {
            "agent_version": VERSION,
            "capture_mode": self.monitor.mode if self.monitor else "off",
            "host": {"id": machine_id(), "hostname": socket.gethostname(), "os": os_name(),
                     "ip": ip, "uptime_s": uptime, "cores": os.cpu_count()},
            "metrics": self.metrics(),
            "listening": sorted(listening),
            "subnets": [str(n) for n in self.nets],
            "connections": [{"src": s, "port": p, "count": n, "open": p in listening}
                            for (s, p), n in conns.items()],
            "auth": [{"src": s, "user": u, "result": r, "count": n}
                     for (s, u, r), n in self.pending_auth.items()],
        }
        if self.checks and self.cfg.get("checks", True):
            report["checks"] = run_checks(self.checks)
        pending = {"usb": self.usb.drain() if self.usb else [], "files": self.watcher.drain() if self.watcher else {}}
        if pending["usb"] or pending["files"] or self.watcher:
            report["dlp"] = {
                "usb": pending["usb"],
                "files": [{"watch_id": w, "action": a, "path": p, "user": "", "count": n}
                          for (w, a, p), n in pending["files"].items()],
                "watch_status": self.watcher.statuses() if self.watcher else []}
        self._pending_dlp = pending
        if self.cfg.get("discovery", True) and time.time() - self.last_scan >= self.cfg.get("scan_interval", 300):
            report["devices"] = self.discovery.scan(self.nets)
            self.last_scan = time.time()
        return report, conns

    def send(self, report):
        req = urllib.request.Request(
            self.cfg["manager"].rstrip("/") + "/api/agent/report",
            data=json.dumps(report).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.cfg["token"],
                     "User-Agent": "nobet-agent/" + VERSION})
        with urllib.request.urlopen(req, timeout=20, context=self.ssl_ctx) as resp:
            body = resp.read()
        try:
            reply = json.loads(body)
            checks, watches = reply.get("checks"), reply.get("watch_paths")
        except (ValueError, AttributeError):
            return
        if isinstance(checks, list):
            self.checks = checks
        if isinstance(watches, list) and self.dlp:
            self.set_watches([w for w in watches if isinstance(w, dict) and "id" in w][:20])

    def set_watches(self, watches):
        """İzlenen klasör listesi değiştiyse izleyiciyi yeniden kurar."""
        if watches == self.watch_defs:
            return
        if self.watcher:
            self.watcher.close()
        self.watch_defs = watches
        self.watcher = FolderWatcher(watches) if watches else None

    def run_once(self, dry_run=False):
        report, conns = self.collect()
        if dry_run:
            print(json.dumps(report, indent=2, ensure_ascii=False))
            return True
        try:
            self.send(report)
        except (urllib.error.URLError, OSError) as exc:
            # Gönderilemeyen bağlantı/giriş sayaçları bir sonraki rapora eklenir.
            if self.monitor:
                self.monitor.restore(conns)
            if "devices" in report:
                self.last_scan = 0
            if self.usb:
                self.usb.restore(self._pending_dlp["usb"])
            if self.watcher:
                self.watcher.restore(self._pending_dlp["files"])
            print(f"rapor gönderilemedi: {exc}", file=sys.stderr, flush=True)
            return False
        self.pending_auth = {}
        return True

    def run(self):
        interval = max(5, int(self.cfg.get("interval", 30)))
        print(f"Nöbet Agent {VERSION} başladı: {self.cfg['manager']} "
              f"(yakalama: {self.monitor.mode if self.monitor else 'kapalı'}, "
              f"alt ağlar: {', '.join(map(str, self.nets)) or 'yok'})", flush=True)
        time.sleep(1)  # ilk CPU/ağ farkı için kısa ölçüm aralığı
        while True:
            started = time.time()
            try:
                self.run_once()
            except Exception as exc:  # tek turdaki hata ajanı durdurmasın
                print("toplama hatası:", repr(exc), file=sys.stderr, flush=True)
            time.sleep(max(1, interval - (time.time() - started)))


def load_config(args):
    cfg = {}
    if args.config:
        with open(args.config) as f:
            cfg = json.load(f)
    for key, value in (("manager", args.manager or os.environ.get("NOBET_MANAGER")),
                       ("token", args.token or os.environ.get("NOBET_TOKEN")),
                       ("interval", args.interval)):
        if value:
            cfg[key] = value
    if args.insecure:
        cfg["insecure"] = True
    if not cfg.get("manager") or not cfg.get("token"):
        sys.exit("manager adresi ve token gerekli (--config veya --manager/--token)")
    return cfg


def main():
    ap = argparse.ArgumentParser(description="Nöbet Agent")
    ap.add_argument("--config", help="JSON yapılandırma dosyası")
    ap.add_argument("--manager", help="Manager adresi, örn. https://panel.example.com")
    ap.add_argument("--token", help="şirket ajan anahtarı (nbt_...)")
    ap.add_argument("--interval", type=int, help="rapor aralığı (saniye, varsayılan 30)")
    ap.add_argument("--insecure", action="store_true", help="TLS sertifikasını doğrulama (yalnızca test)")
    ap.add_argument("--once", action="store_true", help="tek rapor gönder ve çık")
    ap.add_argument("--print", dest="dry_run", action="store_true", help="raporu göndermeden ekrana yaz")
    args = ap.parse_args()
    agent = Agent(load_config(args))
    if args.once or args.dry_run:
        time.sleep(1)
        sys.exit(0 if agent.run_once(dry_run=args.dry_run) else 1)
    agent.run()


if __name__ == "__main__":
    main()

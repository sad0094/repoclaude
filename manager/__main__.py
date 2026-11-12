"""Nöbet Manager: `python3 -m manager --port 8080`"""
import argparse
import getpass
import os
import secrets
import sys
import threading
import time

from .core import Engine
from .db import DB, hash_password
from .notify import Notifier
from .web import App, make_server


def build(db_path):
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    db = DB(db_path)
    notifier = Notifier(db)
    engine = Engine(db, notifier)
    return db, notifier, engine, App(db, engine, notifier)


def tick_loop(engine, interval=15):
    while True:
        time.sleep(interval)
        try:
            engine.tick()
        except Exception as exc:
            print("periyodik kontrol hatası:", repr(exc), file=sys.stderr, flush=True)


def main():
    ap = argparse.ArgumentParser(description="Nöbet merkezi yönetim paneli")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--db", default=os.environ.get("NOBET_DB", "data/nobet.db"))
    ap.add_argument("--cert", help="TLS sertifikası (PEM)")
    ap.add_argument("--key", help="TLS özel anahtarı (PEM)")
    ap.add_argument("--trust-proxy", action="store_true",
                    help="istemci adresini X-Forwarded-For başlığından al (yalnızca ters vekil arkasında)")
    ap.add_argument("--set-password", action="store_true", help="bir kullanıcının parolasını değiştir ve çık")
    ap.add_argument("--user", default="admin", help="--set-password için kullanıcı adı (varsayılan: admin)")
    args = ap.parse_args()

    db, notifier, engine, app = build(args.db)

    if args.set_password:
        user = db.one("SELECT id FROM users WHERE username=?", (args.user,))
        if not user:
            sys.exit(f"Kullanıcı bulunamadı: {args.user}")
        password = getpass.getpass(f"{args.user} için yeni parola: ")
        if len(password) < 8:
            sys.exit("Parola en az 8 karakter olmalı.")
        db.write("UPDATE users SET password_hash=?, active=1 WHERE id=?", (hash_password(password), user["id"]))
        db.write("DELETE FROM sessions WHERE user_id=?", (user["id"],))
        print("Parola güncellendi.")
        return

    if not db.one("SELECT 1 FROM users"):
        password = os.environ.get("NOBET_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
        db.create_user("admin", password, "admin")
        if not os.environ.get("NOBET_ADMIN_PASSWORD"):
            print(f"İlk kurulum: yönetici hesabı oluşturuldu -> kullanıcı: admin  parola: {password}\n"
                  "Bu parola bir daha gösterilmez; değiştirmek için --set-password kullanın.", flush=True)

    notifier.start()
    threading.Thread(target=tick_loop, args=(engine,), daemon=True, name="tick").start()
    server = make_server(app, args.host, args.port, args.cert, args.key, args.trust_proxy)
    scheme = "https" if args.cert else "http"
    print(f"Nöbet Manager {scheme}://{args.host}:{args.port} adresinde çalışıyor (veritabanı: {args.db})", flush=True)
    if not args.cert:
        print("Uyarı: TLS kapalı. Ajan anahtarları açık metin gider; --cert/--key verin "
              "veya TLS sonlandıran bir ters vekil kullanın.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

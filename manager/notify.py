"""Bildirim kanalları: Telegram botu ve genel webhook (Slack/Teams/çağrı servisi köprüsü için)."""
import json
import os
import queue
import sys
import threading
import urllib.error
import urllib.request

TELEGRAM_API = os.environ.get("NOBET_TELEGRAM_API", "https://api.telegram.org")


def _post_json(url, payload, timeout=10):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


class Notifier(threading.Thread):
    """Bildirimleri istek işleyicilerini bekletmeden arka planda gönderir."""

    def __init__(self, db):
        super().__init__(daemon=True, name="notifier")
        self.db = db
        self.queue = queue.Queue()
        self.last_error = ""

    def send(self, message):
        """message: {text, chat_id (boş olabilir), event: {...}}"""
        self.queue.put(message)

    def run(self):
        while True:
            message = self.queue.get()
            try:
                self.deliver(message)
            except Exception as exc:  # bildirim hatası servisi düşürmemeli
                self.last_error = str(exc)
                print("bildirim gönderilemedi:", exc, file=sys.stderr)
            finally:
                self.queue.task_done()

    def deliver(self, message):
        """Yapılandırılmış tüm kanallara gönderir; gönderilen kanal adlarını döndürür."""
        cfg = self.db.settings()
        sent, errors = [], []
        token = cfg["telegram_bot_token"]
        chat_id = message.get("chat_id") or cfg["telegram_chat_id"]
        if token and chat_id:
            try:
                _post_json(f"{TELEGRAM_API}/bot{token}/sendMessage", {
                    "chat_id": chat_id, "text": message["text"],
                    "parse_mode": "HTML", "disable_web_page_preview": True})
                sent.append("telegram")
            except (urllib.error.URLError, OSError) as exc:
                # Hata metnine bot token'ı sızmasın.
                errors.append("telegram: " + str(exc).replace(token, "***"))
        if cfg["webhook_url"]:
            try:
                _post_json(cfg["webhook_url"], {"text": message["text"], **message.get("event", {})})
                sent.append("webhook")
            except (urllib.error.URLError, OSError, ValueError) as exc:
                errors.append("webhook: " + str(exc))
        if errors:
            self.last_error = "; ".join(errors)
            if not sent:
                raise RuntimeError(self.last_error)
        elif sent:
            self.last_error = ""
        return sent

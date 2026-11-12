"""Zaman tabanlı tek kullanımlık parola (TOTP, RFC 6238): SHA-1, 6 hane, 30 saniye.

Google Authenticator, Microsoft Authenticator, Authy vb. uygulamalarla uyumludur."""
import base64
import hmac
import secrets
import struct
import time
import urllib.parse

STEP = 30
RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # karışan karakterler (0/o, 1/l/i) yok


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()


def code_at(secret, step):
    key = base64.b32decode(secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), "sha1").digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def verify(secret, code, last_step=0, now=None, window=1):
    """Kod geçerliyse eşleşen zaman adımını döndürür, değilse None.

    Saat kayması için ±window adım kabul edilir. last_step ve öncesi reddedilir:
    aynı kod ikinci kez kullanılamaz (tekrar oynatma koruması)."""
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != 6 or not secret:
        return None
    current = int((now if now is not None else time.time()) // STEP)
    matched = None
    for step in range(current - window, current + window + 1):
        # Zamanlama farkı sızdırmamak için tüm adaylar sabit zamanlı karşılaştırılır.
        if hmac.compare_digest(code_at(secret, step), code) and step > (last_step or 0):
            matched = step
    return matched


def provisioning_uri(secret, username, issuer="Nobet"):
    label = urllib.parse.quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={urllib.parse.quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def new_recovery_codes(count=8):
    pick = lambda: "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(4))
    return [f"{pick()}-{pick()}" for _ in range(count)]


def normalize_recovery(code):
    text = "".join(ch for ch in str(code).lower() if ch.isalnum())
    return f"{text[:4]}-{text[4:]}" if len(text) == 8 else ""

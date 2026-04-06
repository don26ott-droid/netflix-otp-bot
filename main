#!/usr/bin/env python3
"""
Netflix OTP Forwarder — Flask App
Monitors Gmail for Netflix sign-in emails, extracts the OTP code,
device/location info, and sends a clean message to Telegram.
Runs the polling loop in a background thread while Flask handles HTTP.
"""

import imaplib
import email
import os
import re
import time
import json
import threading
import urllib.request
import urllib.parse
from datetime import datetime
from email.header import decode_header
from html.parser import HTMLParser

from flask import Flask

GMAIL_ADDRESS = os.environ.get("GMAIL_ADDRESS", "")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993
CHECK_INTERVAL_SECONDS = 30
STATE_FILE = os.path.join(os.path.dirname(__file__), ".state.json")

NETFLIX_SENDER_PATTERN = re.compile(r"netflix\.com", re.IGNORECASE)

NETFLIX_SUBJECT_KEYWORDS = [
    "sign in",
    "signin",
    "sign-in",
    "verification",
    "verify",
    "access",
    "login",
    "log in",
    "new device",
    "account access",
    "code",
]

OTP_PATTERN = re.compile(r"\b(\d{4,8})\b")

OTP_CONTEXT_KEYWORDS = re.compile(
    r"(code|otp|one.?time|sign.?in|verification|passcode|pin)",
    re.IGNORECASE,
)

DEVICE_PATTERNS = [
    re.compile(r"(?:device|browser|app)[:\s]+([^\n\r<]{3,60})", re.IGNORECASE),
    re.compile(
        r"(?:from|on|using)\s+(?:a\s+)?([A-Za-z][\w\s]{2,40}"
        r"(?:Chrome|Firefox|Safari|Edge|Android|iPhone|iPad|Windows|Mac|Linux)[^\n\r<]{0,30})",
        re.IGNORECASE,
    ),
]

LOCATION_PATTERNS = [
    re.compile(
        r"(?:location|ip address|city|country|from)[:\s]+([^\n\r<]{3,80})",
        re.IGNORECASE,
    ),
    re.compile(r"IP[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.IGNORECASE),
]


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._parts = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head"):
            self._skip = False
        if tag in ("p", "br", "div", "tr", "li"):
            self._parts.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self._parts.append(data)

    def get_text(self):
        return re.sub(r"\n{3,}", "\n\n", "".join(self._parts)).strip()


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return {"seen_ids": data, "last_otp": None, "last_message_id": None}
            return data
    return {"seen_ids": [], "last_otp": None, "last_message_id": None}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def decode_mime_words(s):
    if not s:
        return ""
    parts = decode_header(s)
    result = []
    for part, charset in parts:
        if isinstance(part, bytes):
            result.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            result.append(part)
    return "".join(result)


def get_email_parts(msg):
    plain = ""
    html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd:
                continue
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                decoded = payload.decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
                if ct == "text/plain":
                    plain += decoded
                elif ct == "text/html":
                    html += decoded
            except Exception:
                pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                decoded = payload.decode(
                    msg.get_content_charset() or "utf-8", errors="replace"
                )
                if msg.get_content_type() == "text/html":
                    html = decoded
                else:
                    plain = decoded
        except Exception:
            pass
    return plain, html


def html_to_text(html):
    extractor = TextExtractor()
    try:
        extractor.feed(html)
        return extractor.get_text()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)


def is_netflix_email(sender, subject):
    return bool(NETFLIX_SENDER_PATTERN.search(sender)) and any(
        kw in subject.lower() for kw in NETFLIX_SUBJECT_KEYWORDS
    )


def extract_otp(subject, plain, html):
    html_text = html_to_text(html)
    full_text = f"{plain}\n{html_text}"

    def is_likely_otp(num_str):
        num = int(num_str)
        return not (2000 <= num <= 2099)

    for line in full_text.splitlines():
        if OTP_CONTEXT_KEYWORDS.search(line):
            for m in OTP_PATTERN.finditer(line):
                if is_likely_otp(m.group(1)):
                    return m.group(1)

    for m in OTP_PATTERN.finditer(subject):
        if is_likely_otp(m.group(1)):
            return m.group(1)

    for m in OTP_PATTERN.finditer(full_text):
        if is_likely_otp(m.group(1)):
            return m.group(1)

    return None


def extract_device_location(plain, html):
    html_text = html_to_text(html)
    full_text = f"{plain}\n{html_text}"
    device = None
    location = None

    for pattern in DEVICE_PATTERNS:
        m = pattern.search(full_text)
        if m:
            candidate = m.group(1).strip().strip(".,:")
            if len(candidate) > 2:
                device = candidate
                break

    for pattern in LOCATION_PATTERNS:
        m = pattern.search(full_text)
        if m:
            candidate = m.group(1).strip().strip(".,:")
            if len(candidate) > 2:
                location = candidate
                break

    return device, location


def escape_html(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def delete_telegram_message(message_id):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/deleteMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "message_id": message_id}
    data = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            if result.get("ok"):
                print("  [Telegram] Previous message deleted.")
            else:
                print(
                    f"  [Telegram] Delete failed: {result.get('description', result)}"
                )
    except Exception as e:
        print(f"  [Telegram] Delete error: {e}")


def send_telegram(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }
    data = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            if result.get("ok"):
                msg_id = result["result"]["message_id"]
                print(f"  [Telegram] Sent (id={msg_id}).")
                return msg_id
            else:
                print(f"  [Telegram] API error: {result}")
                return _send_telegram_plain(message)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"  [Telegram] HTTP {e.code}: {body}")
        return _send_telegram_plain(message)
    except Exception as e:
        print(f"  [Telegram] Error: {e}")
        return None


def _send_telegram_plain(message):
    plain = re.sub(r"<[^>]+>", "", message)
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": plain}
    data = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            if result.get("ok"):
                print("  [Telegram] Plain-text fallback sent.")
                return result["result"]["message_id"]
    except Exception as e:
        print(f"  [Telegram] Plain-text fallback error: {e}")
    return None


def check_inbox(state):
    seen_ids = set(state["seen_ids"])
    last_otp = state.get("last_otp")
    last_message_id = state.get("last_message_id")

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Checking inbox...")
    try:
        mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        mail.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
        mail.select("INBOX")

        _, data = mail.search(None, "UNSEEN")
        email_ids = data[0].split()

        if not email_ids:
            print("  No new unread emails.")
            mail.logout()
            return state

        print(f"  Found {len(email_ids)} unread email(s).")

        for eid in email_ids:
            eid_str = eid.decode()
            if eid_str in seen_ids:
                continue

            _, msg_data = mail.fetch(eid, "(RFC822)")
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)

            subject = decode_mime_words(msg.get("Subject", "(no subject)"))
            sender = decode_mime_words(msg.get("From", "unknown"))
            plain, html = get_email_parts(msg)

            seen_ids.add(eid_str)
            print(f'  Email: "{subject}" from {sender}')

            if not is_netflix_email(sender, subject):
                print("  Not a Netflix email, skipping.")
                continue

            print("  Netflix email detected!")
            otp = extract_otp(subject, plain, html)
            device, location = extract_device_location(plain, html)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if not otp:
                print("  No OTP code found.")
                state["seen_ids"] = list(seen_ids)
                continue

            if otp == last_otp:
                print(f"  OTP {otp} already sent — skipping duplicate.")
                state["seen_ids"] = list(seen_ids)
                continue

            print(f"  OTP: {otp} | Device: {device} | Location: {location}")

            if last_message_id:
                delete_telegram_message(last_message_id)

            device_line = f"\n📱 Device: {escape_html(device)}" if device else ""
            location_line = (
                f"\n🌍 Location: {escape_html(location)}" if location else ""
            )

            message = (
                f"🔐 <b>Netflix Sign-In Code</b>\n\n"
                f"👉 <b>{otp}</b>"
                f"{device_line}"
                f"{location_line}\n"
                f"⏱ Time: {timestamp}\n\n"
                f"Enter the code above on your device to sign in to Netflix.\n"
                f"This code will expire in 15 minutes."
            )

            new_message_id = send_telegram(message)
            last_otp = otp
            last_message_id = new_message_id
            state["last_otp"] = last_otp
            state["last_message_id"] = last_message_id

        mail.logout()
        state["seen_ids"] = list(seen_ids)
        return state

    except imaplib.IMAP4.error as e:
        print(f"  [IMAP Error] {e}")
        return state
    except Exception as e:
        print(f"  [Error] {e}")
        return state


def bot_loop():
    state = load_state()
    while True:
        try:
            state = check_inbox(state)
            save_state(state)
        except Exception as e:
            print(f"[Unexpected error] {e}")
        time.sleep(CHECK_INTERVAL_SECONDS)


app = Flask(__name__)


@app.route("/")
def index():
    return "Bot is running", 200


def start_bot():
    missing = [
        k
        for k in [
            "GMAIL_ADDRESS",
            "GMAIL_APP_PASSWORD",
            "TELEGRAM_BOT_TOKEN",
            "TELEGRAM_CHAT_ID",
        ]
        if not os.environ.get(k)
    ]
    if missing:
        print(
            f"[Warning] Missing env vars: {', '.join(missing)} — bot thread not started."
        )
        return

    send_telegram(
        f"✅ <b>Netflix OTP Forwarder started</b>\n"
        f"Monitoring <code>{GMAIL_ADDRESS}</code> for Netflix sign-in emails.\n"
        f"Checking every {CHECK_INTERVAL_SECONDS} seconds."
    )
    thread = threading.Thread(target=bot_loop, daemon=True)
    thread.start()
    print("Bot thread started.")


start_bot()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    print(f"Starting Flask dev server on port {port}...")
    app.run(host="0.0.0.0", port=port)

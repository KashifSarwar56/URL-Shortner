from flask import Flask, render_template, request, redirect, url_for
import qrcode
import os
import requests
from io import BytesIO
import base64

app = Flask(__name__)

# Google Safe Browsing API Key
API_KEY = "AIzaSyBW0s8H5YZnWrxj4yAuC-x9QjWnKt_vu7U"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Storage for shortened URLs & analytics
url_database = {}
click_analytics = {}

# Function to check if URL is safe
def check_url_safety(url):
    payload = {
        "client": {"clientId": "url-shortener-app", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(f"{SAFE_BROWSING_URL}?key={API_KEY}", json=payload)
    result = response.json()

    if "matches" in result:
        return False  # URL is suspicious
    return True  # URL is safe

@app.route("/", methods=["GET", "POST"])
def home():
    short_url = None
    qr_code = None
    safety_status = None

    if request.method == "POST":
        long_url = request.form.get("url")

        # Check URL safety
        is_safe = check_url_safety(long_url)
        safety_status = "Safe ✅" if is_safe else "Suspicious ❌"

        # Shorten the URL
        short_code = str(len(url_database) + 1)
        short_url = request.host_url + short_code
        url_database[short_code] = long_url
        click_analytics[short_code] = 0

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(short_url)
        qr.make(fit=True)
        img = qr.make_image(fill="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode()

    return render_template("index.html", short_url=short_url, qr_code=qr_code, safety_status=safety_status)

@app.route("/<short_code>")
def redirect_to_url(short_code):
    if short_code in url_database:
        click_analytics[short_code] += 1
        return redirect(url_database[short_code])
    return "Invalid URL", 404

@app.route("/analytics")
def analytics():
    return render_template("analytics.html", analytics=click_analytics, urls=url_database)

if __name__ == "__main__":
    app.run(debug=True)

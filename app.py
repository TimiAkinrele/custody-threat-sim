from flask import Flask, render_template, request
import os
import requests
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# API Keys (do not change these variable names)
ABUSEIPDB_KEY = os.getenv('ABUSE_IP_DB_API_KEY')
VT_KEY = os.getenv('VIRUS_TOTAL_API_KEY')
SHODAN_KEY = os.getenv('SHODAN_API_KEY')

# Ensure API keys are set
if not ABUSEIPDB_KEY or not VT_KEY or not SHODAN_KEY:
    raise ValueError("API keys for AbuseIPDB, VirusTotal, and Shodan must be set as environment variables.")

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    blocked_ips = []

    if request.method == "POST":
        # Debug: Log form data
        print("Form data received:", request.form)
        
        # Use the correct key from the form: 'ip_address'
        ip = request.form.get("ip_address")
        if not ip:
            return "Error: No IP Address provided!", 400

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            # AbuseIPDB API Request
            abuse_response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip}
            )
            abuse_data = abuse_response.json()
            abuse_score = abuse_data.get("data", {}).get("abuseConfidenceScore", 0)

            # VirusTotal API Request
            vt_response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VT_KEY}
            )
            vt_data = vt_response.json()

            # Shodan API Request
            shodan_response = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}"
            )
            shodan_data = shodan_response.json()

            # Decide whether to "block" the IP (simulate)
            is_malicious = abuse_score >= 50 or "malicious" in vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            if is_malicious:
                blocked_ips.append(ip)

            # Log the lookup details to ip_logs.txt
            with open("ip_logs.txt", "a") as f:
                f.write(f"{timestamp} - IP: {ip} | Abuse Score: {abuse_score} | Malicious: {is_malicious}\n")

            result = {
                "ip": ip,
                "abuse": abuse_data,
                "virustotal": vt_data,
                "shodan": shodan_data,
                "blocked": is_malicious
            }

        except requests.exceptions.RequestException as e:
            return f"Error occurred during IP lookup: {e}", 500

        return render_template("results.html", result=result)

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)


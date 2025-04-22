import os
import subprocess
import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for
from datetime import datetime
from dotenv import load_dotenv
import pandas as pd
import plotly.express as px
import mpc_sim
from simulate_tx import MPCWallet

# Load environment variables
load_dotenv()
ABUSEIPDB_KEY = os.getenv('ABUSE_IP_DB_API_KEY')
VT_KEY = os.getenv('VIRUS_TOTAL_API_KEY')
SHODAN_KEY = os.getenv('SHODAN_API_KEY')

if not ABUSEIPDB_KEY or not VT_KEY or not SHODAN_KEY:
    raise ValueError("Missing API keys in .env")

app = Flask(__name__)

# Instantiate the MPC wallet once
wallet = MPCWallet()

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/", methods=["GET"])
def default():
    return redirect(url_for('home'))

@app.route("/index", methods=["GET", "POST"])
def index():
    result = {}
    if request.method == "POST":
        ip = request.form.get("ip_address")
        if not ip:
            return "Error: No IP provided", 400
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # AbuseIPDB
        abuse = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip}
        ).json()
        sc = abuse.get("data", {}).get("abuseConfidenceScore", 0)
        tot = abuse.get("data", {}).get("totalReports", 0)

        # VirusTotal
        vt = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_KEY}
        ).json()

        # Shodan
        sh = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}"
        ).json()

        # Decide whether malicious and what score to log
        if sc > 0 or tot > 0:
            is_mal = sc >= 50 or "malicious" in vt.get("data", {})\
                                     .get("attributes", {})\
                                     .get("last_analysis_stats", {})
            log_score = sc
        else:
            is_mal = False
            log_score = 0

        # Log lookup
        with open("ip_logs.txt", "a") as f:
            f.write(f"{ts} - IP: {ip} | Abuse Score: {log_score} | Malicious: {is_mal}\n")

        # Block if malicious
        if is_mal:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

        result = {
            "ip": ip,
            "abuse_score": log_score,
            "total_reports": tot,
            "virustotal": vt,
            "shodan": sh,
            "blocked": is_mal
        }
        return render_template("results.html", result=result)

    return render_template("index.html", result={})

@app.route("/api/logs")
def api_logs():
    entries = []
    with open("ip_logs.txt") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(" - ", 1)
            if len(parts) != 2:
                continue
            ts, rest = parts
            fields = rest.split(" | ")
            if len(fields) != 3:
                continue
            try:
                ip_val = fields[0].split("IP: ")[1]
                abuse_score = int(fields[1].split("Abuse Score: ")[1])
                mal = fields[2].split("Malicious: ")[1] == "True"
            except (IndexError, ValueError):
                continue
            entries.append({
                "timestamp": ts,
                "ip": ip_val,
                "score": abuse_score,
                "malicious": mal
            })
    return jsonify(entries)

@app.route("/dashboard")
def dashboard():
    logs = api_logs().get_json()
    if not logs:
        chart_html = "<p>No log data available to display.</p>"
    else:
        df = pd.DataFrame(logs)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["score"] = df.apply(lambda r: r["score"] if r["malicious"] else 0, axis=1)
        fig = px.line(df, x="timestamp", y="score", title="Abuse Score Over Time for IP Lookups")
        chart_html = fig.to_html(full_html=False)
    return render_template("dashboard.html", chart_html=chart_html)

@app.route("/mpc")
def mpc():
    return render_template(
        "mpc.html",
        secret_hex=hex(mpc_sim.SECRET),
        shares=mpc_sim.shares,
        parties=mpc_sim.PARTIES,
        recon1=("Client", "Copper", hex(mpc_sim.reconstruct("Client", "Copper"))),
        recon2=("Client", "TTP", hex(mpc_sim.reconstruct("Client", "TTP"))),
        recon3=("Copper", "TTP", hex(mpc_sim.reconstruct("Copper", "TTP")))
    )

@app.route("/simulate", methods=["GET", "POST"])
def simulate():
    result = {}
    if request.method == "POST":
        party_a = request.form.get("party_a")
        party_b = request.form.get("party_b")
        tx = {
            "from": request.form.get("from_addr"),
            "to": request.form.get("to_addr"),
            "amount": float(request.form.get("amount"))
        }
        sk = wallet.reconstruct_sk(party_a, party_b)
        sig = wallet.sign_transaction(sk, tx)
        verified = wallet.verify_signature(sig, tx)
        result = {
            "public_key": wallet.public_key_hex,
            "used_parties": [party_a, party_b],
            "tx": tx,
            "signature": sig,
            "verified": verified
        }
    return render_template("simulate.html", parties=wallet.parties, result=result)

if __name__ == "__main__":
    app.run(debug=True)

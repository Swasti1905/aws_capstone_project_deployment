from flask import Flask, render_template, request, redirect, url_for, session
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
import requests
import os
from werkzeug.security import generate_password_hash, check_password_hash

# ================= APP CONFIG =================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

# ================= AWS CONFIG =================
REGION = os.environ.get("AWS_REGION", "us-east-1")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

users_table = dynamodb.Table("Users")
watchlists_table = dynamodb.Table("Watchlists")
alerts_table = dynamodb.Table("PriceAlerts")
admin_table = dynamodb.Table("AdminUsers")

# ================= LOCAL FALLBACK DATA =================
CRYPTO_DATABASE = {
    "BTC": {"name": "Bitcoin", "symbol": "BTC", "current_price": 42500},
    "ETH": {"name": "Ethereum", "symbol": "ETH", "current_price": 2300},
    "XRP": {"name": "Ripple", "symbol": "XRP", "current_price": 2.10},
}

# ================= HELPERS =================
def send_sns(subject, message):
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    except ClientError as e:
        print("SNS Error:", e)

def get_user(username):
    return users_table.get_item(Key={"username": username}).get("Item")

def get_watchlist(username):
    res = watchlists_table.get_item(Key={"username": username})
    return res.get("Item", {}).get("crypto_ids", [])

def save_watchlist(username, crypto_ids):
    watchlists_table.put_item(Item={"username": username, "crypto_ids": crypto_ids})

def get_alerts(username):
    res = alerts_table.get_item(Key={"username": username})
    return res.get("Item", {}).get("alerts", {})

def save_alerts(username, alerts):
    alerts_table.put_item(Item={"username": username, "alerts": alerts})

def get_crypto_details_by_id(coin_id):
    try:
        r = requests.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={
                "ids": coin_id,
                "vs_currencies": "usd",
                "include_market_cap": "true",
                "include_24hr_vol": "true"
            },
            timeout=10
        )
        r.raise_for_status()
        data = r.json().get(coin_id)
        return data
    except:
        return None

def get_crypto_by_search(query):
    try:
        r = requests.get(
            "https://api.coingecko.com/api/v3/search",
            params={"query": query},
            timeout=10
        )
        r.raise_for_status()
        return r.json().get("coins", [])[:5]
    except:
        return []

def check_price_alerts(username):
    alerts = get_alerts(username)
    triggered = []

    for crypto_id, config in alerts.items():
        current = CRYPTO_DATABASE.get(crypto_id, {}).get("current_price", 0)
        threshold = config["threshold"]
        alert_type = config["type"]

        if (alert_type == "above" and current > threshold) or \
           (alert_type == "below" and current < threshold):
            triggered.append(f"{crypto_id} crossed {threshold}")

    return triggered

# ================= AUTH =================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if get_user(username):
            return render_template("signup.html", error="User exists")

        users_table.put_item(Item={
            "username": username,
            "password": generate_password_hash(password),
            "created_at": datetime.utcnow().isoformat()
        })

        save_watchlist(username, [])
        save_alerts(username, {})
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = get_user(username)
        if user and check_password_hash(user["password"], password):
            session["username"] = username

            send_sns("Login", f"{username} logged in")

            for alert in check_price_alerts(username):
                send_sns("Price Alert", alert)

            return redirect(url_for("home"))

        return render_template("login.html", error="Invalid login")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ================= HOME =================
@app.route("/home")
def home():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    watchlist = []

    for cid in get_watchlist(username):
        info = CRYPTO_DATABASE.get(cid) or get_crypto_details_by_id(cid)
        if info:
            watchlist.append({"id": cid, **info})

    return render_template("home.html", watchlist=watchlist)

# ================= SEARCH =================
@app.route("/search", methods=["GET", "POST"])
def search():
    if "username" not in session:
        return redirect(url_for("login"))

    results = []
    if request.method == "POST":
        query = request.form["query"]
        for coin in get_crypto_by_search(query):
            results.append({
                "id": coin["id"],
                "name": coin["name"],
                "symbol": coin["symbol"].upper()
            })

    return render_template("search.html", results=results)

# ================= WATCHLIST =================
@app.route("/add/<crypto_id>")
def add_to_watchlist(crypto_id):
    username = session["username"]
    wl = get_watchlist(username)
    if crypto_id not in wl:
        wl.append(crypto_id)
        save_watchlist(username, wl)
    return redirect(url_for("home"))

@app.route("/remove/<crypto_id>")
def remove_from_watchlist(crypto_id):
    username = session["username"]
    wl = get_watchlist(username)
    if crypto_id in wl:
        wl.remove(crypto_id)
        save_watchlist(username, wl)
    return redirect(url_for("home"))

# ================= ALERTS =================
@app.route("/set-alert/<crypto_id>", methods=["POST"])
def set_alert(crypto_id):
    username = session["username"]
    alerts = get_alerts(username)

    alerts[crypto_id] = {
        "threshold": float(request.form["threshold"]),
        "type": request.form["type"],
        "created_at": datetime.utcnow().isoformat()
    }

    save_alerts(username, alerts)
    return redirect(url_for("home"))

# ================= ADMIN =================
@app.route("/admin")
def admin_dashboard():
    users = users_table.scan().get("Items", [])
    watchlists = watchlists_table.scan().get("Items", [])
    alerts = alerts_table.scan().get("Items", [])

    return render_template(
        "admin_dashboard.html",
        total_users=len(users),
        total_watchlists=len(watchlists),
        total_alerts=len(alerts)
    )

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000,debug=True)

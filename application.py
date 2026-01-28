from flask import Flask, render_template, request, redirect, url_for, session
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
import requests
import os

from werkzeug.security import generate_password_hash, check_password_hash

# ================= APP CONFIG =================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")  # ✅ ENV VAR

# ================= AWS CONFIG =================
REGION = os.environ.get("AWS_REGION", "us-east-1")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

users_table = dynamodb.Table("Users")
admin_table = dynamodb.Table("AdminUsers")
watchlists_table = dynamodb.Table("Watchlists")
alerts_table = dynamodb.Table("PriceAlerts")

# ================= LOCAL FALLBACK DATA =================
CRYPTO_DATABASE = {
    "BTC": {"name": "Bitcoin", "symbol": "BTC", "current_price": 42500},
    "ETH": {"name": "Ethereum", "symbol": "ETH", "current_price": 2300},
    "XRP": {"name": "Ripple", "symbol": "XRP", "current_price": 2.10},
}

# ================= HELPERS =================
def send_login_notification(username):
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="User Login",
            Message=f"User {username} logged in at {datetime.utcnow()}"
        )
    except ClientError as e:
        print("SNS Error:", e)

def get_user(username):
    return users_table.get_item(Key={"username": username}).get("Item")

def get_admin(username):
    return admin_table.get_item(Key={"username": username}).get("Item")

def get_watchlist(username):
    res = watchlists_table.get_item(Key={"username": username})
    return res.get("Item", {}).get("crypto_ids", [])

def save_watchlist(username, crypto_ids):
    watchlists_table.put_item(
        Item={"username": username, "crypto_ids": crypto_ids}
    )

def get_alerts(username):
    res = alerts_table.get_item(Key={"username": username})
    return res.get("Item", {}).get("alerts", {})

def save_alerts(username, alerts):
    alerts_table.put_item(
        Item={"username": username, "alerts": alerts}
    )

# ================= AUTH =================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if get_user(username):
            return render_template("signup.html", error="User already exists")

        users_table.put_item(Item={
            "username": username,
            "password": generate_password_hash(password),  # ✅ HASHED
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
        if user and check_password_hash(user["password"], password):  # ✅ CHECK
            session["username"] = username
            send_login_notification(username)
            return redirect(url_for("home"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ================= USER DASHBOARD =================
@app.route("/home")
def home():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    watchlist_ids = get_watchlist(username)
    watchlist = []

    for cid in watchlist_ids:
        if cid in CRYPTO_DATABASE:
            watchlist.append({"id": cid, **CRYPTO_DATABASE[cid]})

    return render_template("home.html", username=username, watchlist=watchlist)

# ================= WATCHLIST =================
@app.route("/add/<crypto_id>")
def add_to_watchlist(crypto_id):
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    wl = get_watchlist(username)

    if crypto_id not in wl:
        wl.append(crypto_id)
        save_watchlist(username, wl)

    return redirect(url_for("home"))

@app.route("/remove/<crypto_id>")
def remove_from_watchlist(crypto_id):
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    wl = get_watchlist(username)

    if crypto_id in wl:
        wl.remove(crypto_id)
        save_watchlist(username, wl)

    alerts = get_alerts(username)
    alerts.pop(crypto_id, None)
    save_alerts(username, alerts)

    return redirect(url_for("home"))


# ================= PRICE ALERTS =================
@app.route("/set-alert/<crypto_id>", methods=["POST"])
def set_alert(crypto_id):
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    alerts = get_alerts(username)

    alerts[crypto_id] = {
        "threshold": float(request.form["threshold"]),
        "type": request.form["type"],
        "created_at": datetime.utcnow().isoformat()
    }

    save_alerts(username, alerts)
    return redirect(url_for("home"))


# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

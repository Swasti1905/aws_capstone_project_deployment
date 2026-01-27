from flask import Flask, render_template, request, redirect, url_for, session
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
import requests

# ================= APP CONFIG =================
app = Flask(__name__)
app.secret_key = "your_secret_key_here_crypto_tracker"

# ================= AWS CONFIG =================
REGION = "us-east-1"
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:604665149129:aws_capstone_topic"

dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

users_table = dynamodb.Table("Users")
admin_table = dynamodb.Table("AdminUsers")
watchlists_table = dynamodb.Table("Watchlists")
alerts_table = dynamodb.Table("PriceAlerts")

# ================= LOCAL FALLBACK DATA =================
CRYPTO_DATABASE = {
    "BTC": {"name": "Bitcoin", "symbol": "BTC", "current_price": 42500, "market_cap": 830000000000, "volume_24h": 25000000000},
    "ETH": {"name": "Ethereum", "symbol": "ETH", "current_price": 2300, "market_cap": 276000000000, "volume_24h": 12000000000},
    "XRP": {"name": "Ripple", "symbol": "XRP", "current_price": 2.10, "market_cap": 115000000000, "volume_24h": 5000000000},
}

# ================= HELPERS =================
def send_notification(subject, message):
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
    except ClientError as e:
        print("SNS Error:", e)

def get_crypto_details_by_id(coin_id):
    try:
        url = "https://api.coingecko.com/api/v3/simple/price"
        params = {
            "ids": coin_id,
            "vs_currencies": "usd",
            "include_market_cap": "true",
            "include_24hr_vol": "true"
        }
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        return r.json().get(coin_id)
    except:
        return None

def get_user(username):
    return users_table.get_item(Key={"username": username}).get("Item")

def get_admin(username):
    return admin_table.get_item(Key={"username": username}).get("Item")

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

# ================= ROUTES =================
@app.route("/")
def index():
    return redirect(url_for("home")) if "username" in session else render_template("index.html")

# ---------- USER SIGNUP ----------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if get_user(username):
            return render_template("signup.html", error="User already exists")

        users_table.put_item(Item={
            "username": username,
            "password": password,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        save_watchlist(username, [])
        save_alerts(username, {})

        # ✅ USER SIGNUP NOTIFICATION
        send_notification(
            "User Signup",
            f"New user registered: {username}"
        )

        return redirect(url_for("login"))

    return render_template("signup.html")

# ---------- USER LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = get_user(username)
        if user and user["password"] == password:
            session["username"] = username

            # ✅ USER LOGIN NOTIFICATION
            send_notification(
                "User Login",
                f"User {username} logged in at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )

            return redirect(url_for("home"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

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
        else:
            api = get_crypto_details_by_id(cid)
            if api:
                watchlist.append({
                    "id": cid,
                    "name": cid,
                    "symbol": cid.upper(),
                    "current_price": api.get("usd", 0),
                    "market_cap": api.get("usd_market_cap", 0),
                    "volume_24h": api.get("usd_24h_vol", 0)
                })

    return render_template("home.html", username=username, watchlist=watchlist)

# ================= ADMIN =================
# ---------- ADMIN SIGNUP ----------
@app.route("/admin/signup", methods=["GET", "POST"])
def admin_signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if get_admin(username):
            return render_template("admin_signup.html", error="Admin exists")

        admin_table.put_item(Item={
            "username": username,
            "password": password,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        # ✅ ADMIN SIGNUP NOTIFICATION
        send_notification(
            "Admin Signup",
            f"New admin registered: {username}"
        )

        return redirect(url_for("admin_login"))

    return render_template("admin_signup.html")

# ---------- ADMIN LOGIN ----------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        admin = get_admin(username)
        if admin and admin["password"] == password:
            session["admin"] = username

            # ✅ ADMIN LOGIN NOTIFICATION
            send_notification(
                "Admin Login",
                f"Admin {username} logged in at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )

            return redirect(url_for("admin_dashboard"))

        return render_template("admin_login.html", error="Invalid admin")

    return render_template("admin_login.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    if "admin" not in session:
        return redirect(url_for("admin_login"))

    users = users_table.scan().get("Items", [])
    watchlists = watchlists_table.scan().get("Items", [])
    alerts = alerts_table.scan().get("Items", [])

    return render_template(
        "admin_dashboard.html",
        admin=session["admin"],
        total_users=len(users),
        total_watchlists=len(watchlists),
        total_alerts=len(alerts)
    )

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("index"))

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

import boto3
import os
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from werkzeug.security import generate_password_hash, check_password_hash


from flask import Flask, render_template, request, redirect, url_for, session,flash
from datetime import datetime
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# AWS Configuration 
REGION = 'us-east-1' 

dynamodb = boto3.resource('dynamodb', region_name=REGION)
sns = boto3.client('sns', region_name=REGION)


users_table = dynamodb.Table("Users")
admin_users_table = dynamodb.Table("AdminUsers")
watchlists_table = dynamodb.Table("Watchlists")
alerts_table = dynamodb.Table("PriceAlerts")

def scan_all(table):
    items = []

    try:
        response = table.scan()
        items.extend(response.get('Items', []))

        while 'LastEvaluatedKey' in response:
            response = table.scan(
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items.extend(response.get('Items', []))

    except ClientError as e:
        print("DynamoDB scan error:", e)

    return items




SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:376129862432:project_topic:0aa1423c-4bb6-439f-ac46-ded129c4e8b9'

def send_notification(subject, message):
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN not set. Skipping notification.")
        return

    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
    except ClientError as e:
        print("SNS error:", e)
        

def get_crypto_by_search(query):
    """Fetch cryptocurrency data from CoinGecko API based on search query"""
    try:
        headers = {"User-Agent": "Mozilla/5.0"}  # important

        search_url = "https://api.coingecko.com/api/v3/search"
        params = {'query': query}

        response = requests.get(search_url, params=params, headers=headers, timeout=15)
        response.raise_for_status()

        data = response.json()
        coins = data.get('coins', [])

        if not coins:
            return []

        results = []
        for coin in coins[:5]:
            coin_id = coin.get('id')  # example: "pepe"
            symbol = coin.get('symbol', '').upper()

            if not coin_id:
                continue

            try:
                price_url = "https://api.coingecko.com/api/v3/simple/price"
                price_params = {
                    'ids': coin_id,
                    'vs_currencies': 'usd',
                    'include_market_cap': 'true',
                    'include_24hr_vol': 'true'
                }

                price_response = requests.get(price_url, params=price_params, headers=headers, timeout=15)
                price_response.raise_for_status()
                price_data = price_response.json()

                if coin_id in price_data:
                    price_info = price_data[coin_id]

                    results.append({
                        'id': coin_id,  # store coin_id instead of symbol
                        'name': coin.get('name', 'Unknown'),
                        'symbol': symbol if symbol else coin_id.upper(),
                        'current_price': price_info.get('usd', 0),
                        'market_cap': price_info.get('usd_market_cap', 0),
                        'volume_24h': price_info.get('usd_24h_vol', 0),
                        'from_api': True
                    })

            except Exception as e:
                print("Price fetch failed for:", coin_id, "Error:", e)
                continue

        return results

    except Exception as e:
        print(f"Error fetching from CoinGecko: {e}")
        return []

def get_crypto_details_by_id(coin_id):
    """Fetch live crypto details from CoinGecko using coin_id"""
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        url = "https://api.coingecko.com/api/v3/simple/price"
        params = {
            "ids": coin_id,
            "vs_currencies": "usd",
            "include_market_cap": "true",
            "include_24hr_vol": "true"
        }

        r = requests.get(url, params=params, headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()

        if coin_id in data:
            info = data[coin_id]
            return {
                "current_price": info.get("usd", 0),
                "market_cap": info.get("usd_market_cap", 0),
                "volume_24h": info.get("usd_24h_vol", 0)
            }

        return None
    except Exception as e:
        print("Error fetching coin details:", coin_id, e)
        return None


def check_price_alerts(username):
    """Check price alerts from DynamoDB and trigger SNS notifications"""
    try:
        response = alerts_table.query(
            KeyConditionExpression=Key('username').eq(username)
        )

        alerts = response.get('Items', [])

        for alert in alerts:
            crypto_id = alert['crypto_id']
            threshold = alert['threshold_price']
            alert_type = alert['alert_type']

            crypto_data = get_crypto_details_by_id(crypto_id)
            if not crypto_data:
                continue

            current_price = crypto_data.get('current_price', 0)

            triggered = (
                alert_type == 'above' and current_price > threshold
            ) or (
                alert_type == 'below' and current_price < threshold
            )

            if triggered:
                send_notification(
                    "Price Alert Triggered",
                    f"{crypto_id} is {alert_type} ${threshold}. Current price: ${current_price}"
                )

    except ClientError as e:
        print("Price alert check error:", e)

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('home'))
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():
    error = None

    if request.method == 'POST':
        admin_username = request.form['admin_username']
        admin_password = request.form['admin_password']
        confirm_password = request.form['confirm_password']

        # ❌ Password mismatch
        if admin_password != confirm_password:
            error = "Passwords do not match!"
            return render_template('admin_signup.html', error=error)

        try:
            # 🔍 Check if admin already exists in DynamoDB
            response = admin_users_table.get_item(
                Key={'username': admin_username}
            )

            if 'Item' in response:
                error = "Admin already exists!"
                return render_template('admin_signup.html', error=error)

            # ✅ Hash password before saving
            hashed_password = generate_password_hash(admin_password)

            # ✅ Save admin to DynamoDB
            admin_users_table.put_item(
                Item={
                    'username': admin_username,
                    'password': hashed_password,
                    'created_at': datetime.utcnow().isoformat()
                }
            )

            # 🔔 SNS Notification
            send_notification(
                "New Admin Created",
                f"Admin '{admin_username}' has been created successfully."
            )

            return redirect(url_for('admin_login'))

        except ClientError as e:
            print("Admin signup error:", e)
            error = "AWS error occurred. Please try again."

    return render_template('admin_signup.html', error=error)

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    error = None

    if request.method == 'POST':
        admin_username = request.form['admin_username']
        admin_password = request.form['admin_password']

        try:
            # 🔍 Fetch admin from DynamoDB
            response = admin_users_table.get_item(
                Key={'username': admin_username}
            )

            admin = response.get('Item')

            # ✅ SECURE password check
            if admin and check_password_hash(admin['password'], admin_password):
                admin_users_table.update_item(
                    Key={'username': admin_username},
                    UpdateExpression="SET failed_attempts = :z, locked_until = :z",
                    ExpressionAttributeValues={':z': 0}
                )
                session['admin'] = admin_username

                # 🔔 SNS Notification
                send_notification(
                    "Admin Login",
                    f"Admin '{admin_username}' logged in successfully."
                )

                return redirect(url_for('admin_dashboard'))
            else:
                error = "Invalid admin credentials!"

        except ClientError as e:
            print("Admin login DynamoDB error:", e)
            error = "AWS error occurred. Please try again."

    return render_template('admin_login.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email', '')

        # ✅ Hash the password
        hashed_password = generate_password_hash(password)

        try:
            # 🔍 Check if user already exists
            response = users_table.get_item(
                Key={'username': username}
            )

            if 'Item' in response:
                flash("User already exists!", 'error')
                return render_template('signup.html')

            # ✅ Save user to DynamoDB (hashed password)
            users_table.put_item(
                Item={
                    'username': username,
                    'password': hashed_password,
                    'email': email,
                    'created_at': datetime.utcnow().isoformat()
                }
            )

            # 🔔 SNS Notification
            send_notification(
                "New User Signup",
                f"User '{username}' has signed up successfully."
            )

            flash("Account created successfully! Please login.", 'success')
            return redirect(url_for('login'))

        except ClientError as e:
            print("DynamoDB error:", e)
            flash("AWS error occurred. Try again later.", 'error')
            return render_template('signup.html')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            # 🔍 Fetch user from DynamoDB
            response = users_table.get_item(
                Key={'username': username}
            )

            user = response.get('Item')

            # ✅ Secure password check
            if user and check_password_hash(user['password'], password):
                session['username'] = username

                check_price_alerts(username)

                # 🔔 SNS Notification
                send_notification(
                    "User Login",
                    f"User '{username}' logged in successfully."
                )

                return redirect(url_for('home'))

            else:
                error = "Invalid credentials!"

        except ClientError as e:
            print("DynamoDB error:", e)
            error = "AWS error occurred. Please try again."

    return render_template('login.html', error=error)

@app.route('/home')
def home():
    # 👤 Normal user
    if 'username' in session:
        username = session['username']
        watchlist_data = []

        try:
            response = watchlists_table.query(
                KeyConditionExpression=Key('username').eq(username)
            )

            user_watchlist = response.get('Items', [])

            for item in user_watchlist:
                crypto_id = item['crypto_id']

                # 🌐 Always fetch from CoinGecko
                api_data = get_crypto_details_by_id(crypto_id)

                watchlist_data.append({
                    'id': crypto_id,
                    'name': crypto_id,                  # you can prettify later
                    'symbol': crypto_id.upper(),        # display only
                    'current_price': api_data.get("current_price", 0) if api_data else 0,
                    'market_cap': api_data.get("market_cap", 0) if api_data else 0,
                    'volume_24h': api_data.get("volume_24h", 0) if api_data else 0
                })

        except ClientError as e:
            print("Home watchlist error:", e)

        return render_template(
            'home.html',
            username=username,
            watchlist=watchlist_data,
            is_admin=False
        )

    # 🛡 Admin user
    elif 'admin' in session:
        return redirect(url_for('admin_dashboard'))

    # 🚫 Not logged in
    return redirect(url_for('login'))




@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    results = []
    search_query = ''
    no_results = False

    try:
        # 🔍 Fetch user's watchlist from DynamoDB
        watchlist_res = watchlists_table.query(
            KeyConditionExpression=Key('username').eq(username)
        )
        user_watchlist = [
            item['crypto_id'] for item in watchlist_res.get('Items', [])
        ]

    except ClientError as e:
        print("Watchlist fetch error:", e)
        user_watchlist = []

    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()

        if search_query:
            # 🌐 API-only search (CoinGecko)
            results = get_crypto_by_search(search_query)

            if not results:
                no_results = True

    return render_template(
        'search.html',
        results=results,
        search_query=search_query,
        watchlist=user_watchlist,
        no_results=no_results
    )

@app.route('/watchlist')
def watchlist():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    watchlist_data = []

    try:
        # 🔍 Fetch user's watchlist from DynamoDB
        response = watchlists_table.query(
            KeyConditionExpression=Key('username').eq(username)
        )

        user_watchlist = response.get('Items', [])

        for item in user_watchlist:
            crypto_id = item['crypto_id']

            # 🌐 Always fetch live data from CoinGecko
            api_data = get_crypto_details_by_id(crypto_id)

            current_price = api_data.get("current_price", 0) if api_data else 0
            market_cap = api_data.get("market_cap", 0) if api_data else 0
            volume_24h = api_data.get("volume_24h", 0) if api_data else 0

            # 🔔 Fetch alert config (if any)
            alert_res = alerts_table.get_item(
                Key={'username': username, 'crypto_id': crypto_id}
            )
            alert_config = alert_res.get('Item', {})

            watchlist_data.append({
                'id': crypto_id,
                'alert': alert_config,
                'name': crypto_id,            # display name (can prettify later)
                'symbol': crypto_id.upper(),  # display only
                'current_price': current_price,
                'market_cap': market_cap,
                'volume_24h': volume_24h
            })

    except ClientError as e:
        print("Watchlist fetch error:", e)

    return render_template(
        'watchlist.html',
        watchlist=watchlist_data,
        username=username
    )



@app.route('/add-to-watchlist/<crypto_id>')
def add_to_watchlist(crypto_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    try:
        # 🔍 Check if already exists
        response = watchlists_table.get_item(
            Key={'username': username, 'crypto_id': crypto_id}
        )

        if 'Item' not in response:
            watchlists_table.put_item(
                Item={
                    'username': username,
                    'crypto_id': crypto_id,
                    'added_at': datetime.utcnow().isoformat()
                }
            )

    except ClientError as e:
        print("Add watchlist error:", e)

    return redirect(request.referrer or url_for('search'))

@app.route('/remove-from-watchlist/<crypto_id>')
def remove_from_watchlist(crypto_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    try:
        # ❌ Remove from watchlist
        watchlists_table.delete_item(
            Key={'username': username, 'crypto_id': crypto_id}
        )

        # ❌ Remove alert if exists
        alerts_table.delete_item(
            Key={'username': username, 'crypto_id': crypto_id}
        )

    except ClientError as e:
        print("Remove watchlist error:", e)

    return redirect(url_for('watchlist'))


@app.route('/set-price-alert/<crypto_id>', methods=['POST'])
def set_price_alert(crypto_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    threshold_price = float(request.form.get('threshold_price', 0))
    alert_type = request.form.get('alert_type', 'above')

    try:
        alerts_table.put_item(
            Item={
                'username': username,
                'crypto_id': crypto_id,
                'threshold_price': threshold_price,
                'alert_type': alert_type,
                'triggered': False,
                'created_at': datetime.utcnow().isoformat()
            }
        )

        send_notification(
            "Price Alert Set",
            f"User '{username}' set a {alert_type} alert for {crypto_id} at ${threshold_price}"
        )

    except ClientError as e:
        print("Set price alert error:", e)

    return redirect(url_for('watchlist'))


@app.route('/admin-dashboard')
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    try:
        # NOTE:
        # scan() is used intentionally here because this is an admin-only
        # dashboard with low traffic. For large-scale systems, this would
        # be replaced with indexed queries or analytics pipelines. 

        # 🔍 Fetch data from DynamoDB
        users_items = scan_all(users_table)
        watchlist_items = scan_all(watchlists_table)
        alerts_items = scan_all(alerts_table)


        # 📊 Basic counts
        total_users = len(users_items)
        total_watchlists = len(watchlist_items)
        total_alerts = len(alerts_items)

        # 🔥 Crypto popularity (from watchlists)
        crypto_popularity = {}
        for item in watchlist_items:
            crypto_id = item['crypto_id']
            crypto_popularity[crypto_id] = crypto_popularity.get(crypto_id, 0) + 1

        top_cryptos = sorted(
            crypto_popularity.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        # ⏱ Recent alerts
        recent_alerts = [
            {
                'user': alert['username'],
                'crypto': alert['crypto_id'],
                'threshold': alert['threshold_price'],
                'type': alert['alert_type'],
                'created_at': alert.get('created_at', 'N/A')
            }
            for alert in alerts_items
        ][:10]

        # 👤 Detailed user data
        detailed_users = []

        for user in users_items:
            username = user['username']

            user_watchlists = [
                wl['crypto_id']
                for wl in watchlist_items
                if wl['username'] == username
            ]

            user_alerts = [
                alert
                for alert in alerts_items
                if alert['username'] == username
            ]

            watchlist_details = []
            for crypto_id in user_watchlists:
                alert_info = next(
                    (a for a in user_alerts if a['crypto_id'] == crypto_id),
                    {}
                )

                crypto_data = get_crypto_details_by_id(crypto_id)
                price = crypto_data.get("current_price", 0) if crypto_data else 0

                watchlist_details.append({
                    'symbol': crypto_id,
                    'name': crypto_id,
                    'price': price,
                    'has_alert': bool(alert_info),
                    'alert_type': alert_info.get('alert_type', 'N/A'),
                    'alert_price': alert_info.get('threshold_price', 0)
                })

            detailed_users.append({
                'username': username,
                'email': user.get('email', 'N/A'),
                'watchlist_count': len(user_watchlists),
                'alert_count': len(user_alerts),
                'watchlist': watchlist_details,
                'alerts': user_alerts
            })

        analytics = {
            'total_users': total_users,
            'total_watchlists': total_watchlists,
            'total_alerts': total_alerts,
            'top_cryptos': top_cryptos,
            'recent_alerts': recent_alerts,
            'detailed_users': detailed_users
        }

    except ClientError as e:
        print("Admin dashboard error:", e)
        analytics = {}

    return render_template('admin_dashboard.html', analytics=analytics)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('admin', None)
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000,debug=True)

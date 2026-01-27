from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import json
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key_here_crypto_tracker'

# In-memory database (dictionaries)
users = {}  # {username: {password, email, watchlist: [crypto_ids], alerts: {crypto_id: threshold_price}}}
watchlists = {}  # {username: [crypto_ids]}
price_alerts = {}  # {username: {crypto_id: {threshold_price, alert_type: above/below}}}
crypto_data = {}  # Store cached crypto data for analytics

# Mock cryptocurrency data (simulating API calls)
CRYPTO_DATABASE = {
    'BTC': {'name': 'Bitcoin', 'symbol': 'BTC', 'current_price': 42500, 'market_cap': 830000000000, 'volume_24h': 25000000000},
    'ETH': {'name': 'Ethereum', 'symbol': 'ETH', 'current_price': 2300, 'market_cap': 276000000000, 'volume_24h': 12000000000},
    'XRP': {'name': 'Ripple', 'symbol': 'XRP', 'current_price': 2.10, 'market_cap': 115000000000, 'volume_24h': 5000000000},
    'ADA': {'name': 'Cardano', 'symbol': 'ADA', 'current_price': 0.98, 'market_cap': 35000000000, 'volume_24h': 1500000000},
    'SOL': {'name': 'Solana', 'symbol': 'SOL', 'current_price': 175, 'market_cap': 72000000000, 'volume_24h': 3500000000},
    'DOGE': {'name': 'Dogecoin', 'symbol': 'DOGE', 'current_price': 0.38, 'market_cap': 56000000000, 'volume_24h': 2000000000},
}

def send_email_notification(email, subject, message):
    """Simulate email notification (for local testing)"""
    try:
        # For local testing, we'll just log the notification
        print(f"\n{'='*60}")
        print(f"EMAIL NOTIFICATION")
        print(f"{'='*60}")
        print(f"To: {email}")
        print(f"Subject: {subject}")
        print(f"Message: {message}")
        print(f"Time: {datetime.now()}")
        print(f"{'='*60}\n")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

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
    """Check if any price alerts should be triggered"""
    if username not in price_alerts:
        return []
    
    triggered_alerts = []
    for crypto_id, alert_config in price_alerts[username].items():
        current_price = CRYPTO_DATABASE.get(crypto_id, {}).get('current_price', 0)
        threshold = alert_config.get('threshold_price', 0)
        alert_type = alert_config.get('alert_type', 'above')
        
        if alert_type == 'above' and current_price > threshold:
            triggered_alerts.append({
                'crypto': crypto_id,
                'current_price': current_price,
                'threshold': threshold,
                'type': 'above'
            })
        elif alert_type == 'below' and current_price < threshold:
            triggered_alerts.append({
                'crypto': crypto_id,
                'current_price': current_price,
                'threshold': threshold,
                'type': 'below'
            })
    
    return triggered_alerts

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('home'))
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        admin_username = request.form['admin_username']
        admin_password = request.form['admin_password']
        
        if admin_username == 'admin' and admin_password == 'admin123':
            session['admin'] = admin_username
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Invalid admin credentials!"
    return render_template('admin_login.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email', '')
        
        if username in users:
            error = "User already exists!"
        else:
            users[username] = {
                'password': password,
                'email': email,
                'watchlist': [],
                'alerts': {}
            }
            watchlists[username] = []
            price_alerts[username] = {}
            return redirect(url_for('login'))
    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and users[username]['password'] == password:
            session['username'] = username
            # Check for triggered alerts on login
            alerts = check_price_alerts(username)
            if alerts:
                for alert in alerts:
                    message = f"Price alert for {alert['crypto']}: Current price ${alert['current_price']} is {alert['type']} your threshold of ${alert['threshold']}"
                    send_email_notification(users[username]['email'], f"CryptoTrack Alert - {alert['crypto']}", message)
            return redirect(url_for('home'))
        else:
            error = "Invalid credentials!"
    return render_template('login.html', error=error)

@app.route('/home')
def home():
    if 'username' in session:
        username = session['username']
        user_data = users.get(username, {})
        watchlist = user_data.get('watchlist', [])

        watchlist_data = []
        for crypto_id in watchlist:

            # Local DB crypto
            if crypto_id in CRYPTO_DATABASE:
                crypto_info = CRYPTO_DATABASE[crypto_id]
                watchlist_data.append({
                    'id': crypto_id,
                    'name': crypto_info.get('name', crypto_id),
                    'symbol': crypto_info.get('symbol', crypto_id.upper()),
                    'current_price': crypto_info.get('current_price', 0),
                    'market_cap': crypto_info.get('market_cap', 0),
                    'volume_24h': crypto_info.get('volume_24h', 0)
                })

            # API crypto
            else:
                api_data = get_crypto_details_by_id(crypto_id)
                watchlist_data.append({
                    'id': crypto_id,
                    'name': crypto_id,
                    'symbol': crypto_id.upper(),
                    'current_price': api_data.get("current_price", 0) if api_data else 0,
                    'market_cap': api_data.get("market_cap", 0) if api_data else 0,
                    'volume_24h': api_data.get("volume_24h", 0) if api_data else 0
                })

        return render_template('home.html', username=username, watchlist=watchlist_data, is_admin=False)

    elif 'admin' in session:
        return redirect(url_for('admin_dashboard'))

    return redirect(url_for('login'))


@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    results = []
    search_query = ''
    no_results = False
    
    # Initialize user's watchlist if it doesn't exist
    if username not in users:
        users[username] = {'watchlist': []}
    if username not in watchlists:
        watchlists[username] = []
    
    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        
        if search_query:
            # First, check local database
            search_upper = search_query.upper()
            for crypto_id, crypto_info in CRYPTO_DATABASE.items():
                if search_upper in crypto_id or search_upper in crypto_info['name'].upper():
                    results.append({
                        'id': crypto_id,
                        'name': crypto_info['name'],
                        'symbol': crypto_info['symbol'],
                        'current_price': crypto_info['current_price'],
                        'market_cap': crypto_info['market_cap'],
                        'volume_24h': crypto_info['volume_24h']
                    })
            
            # If no results in local database, fetch from CoinGecko API
            if not results:
                api_results = get_crypto_by_search(search_query)
                if api_results:  # Only extend if we got results
                    results.extend(api_results)
            
            # If still no results, mark it
            if not results:
                no_results = True
    
    user_watchlist = users.get(username, {}).get('watchlist', [])
    return render_template('search.html', 
                         results=results, 
                         search_query=search_query, 
                         watchlist=user_watchlist, 
                         no_results=no_results)

@app.route('/watchlist')
def watchlist():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_watchlist = users.get(username, {}).get('watchlist', [])
    watchlist_data = []

    for crypto_id in user_watchlist:
        # if crypto exists in local DB
        if crypto_id in CRYPTO_DATABASE:
            crypto_info = CRYPTO_DATABASE[crypto_id]
            current_price = crypto_info.get("current_price", 0)
            market_cap = crypto_info.get("market_cap", 0)
            volume_24h = crypto_info.get("volume_24h", 0)
            name = crypto_info.get("name", crypto_id)
            symbol = crypto_info.get("symbol", crypto_id.upper())

        else:
            # otherwise fetch from API using coin_id
            api_data = get_crypto_details_by_id(crypto_id)
            current_price = api_data.get("current_price", 0) if api_data else 0
            market_cap = api_data.get("market_cap", 0) if api_data else 0
            volume_24h = api_data.get("volume_24h", 0) if api_data else 0
            name = crypto_id
            symbol = crypto_id.upper()

        alert_config = price_alerts.get(username, {}).get(crypto_id, {})

        watchlist_data.append({
            'id': crypto_id,
            'alert': alert_config,
            'name': name,
            'symbol': symbol,
            'current_price': current_price,
            'market_cap': market_cap,
            'volume_24h': volume_24h
        })

    return render_template('watchlist.html', watchlist=watchlist_data, username=username)


@app.route('/add-to-watchlist/<crypto_id>')
def add_to_watchlist(crypto_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Initialize user data if it doesn't exist
    if username not in users:
        users[username] = {'watchlist': []}
    if username not in watchlists:
        watchlists[username] = []
    
    # Add to watchlist if not already there
    if crypto_id not in users[username]['watchlist']:
        users[username]['watchlist'].append(crypto_id)
        watchlists[username].append(crypto_id)
    
    # Redirect back to the search page with the same search query
    return redirect(request.referrer or url_for('search'))

@app.route('/remove-from-watchlist/<crypto_id>')
def remove_from_watchlist(crypto_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    if username in users and crypto_id in users[username]['watchlist']:
        users[username]['watchlist'].remove(crypto_id)
        watchlists[username].remove(crypto_id)
        if crypto_id in price_alerts.get(username, {}):
            del price_alerts[username][crypto_id]
    
    return redirect(url_for('watchlist'))

@app.route('/set-price-alert/<crypto_id>', methods=['POST'])
def set_price_alert(crypto_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    threshold_price = float(request.form.get('threshold_price', 0))
    alert_type = request.form.get('alert_type', 'above')
    
    if username not in price_alerts:
        price_alerts[username] = {}
    
    price_alerts[username][crypto_id] = {
        'threshold_price': threshold_price,
        'alert_type': alert_type,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return redirect(url_for('watchlist'))

@app.route('/admin-dashboard')
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    # Calculate analytics
    total_users = len(users)
    total_watchlists = sum(len(users[user].get('watchlist', [])) for user in users)
    total_alerts = sum(len(price_alerts.get(user, {})) for user in price_alerts)

    # Get top cryptocurrencies by watchlist count
    crypto_popularity = {}
    for user in users:
        for crypto in users[user].get('watchlist', []):
            crypto_popularity[crypto] = crypto_popularity.get(crypto, 0) + 1

    top_cryptos = sorted(crypto_popularity.items(), key=lambda x: x[1], reverse=True)[:5]

    # Get recent alerts
    recent_alerts = []
    for user in price_alerts:
        for crypto, alert in price_alerts[user].items():
            recent_alerts.append({
                'user': user,
                'crypto': crypto,
                'threshold': alert.get('threshold_price', 0),
                'type': alert.get('alert_type', 'above'),
                'created_at': alert.get('created_at', 'N/A')
            })

    # Get detailed user information
    detailed_users = []
    for username, user_data in users.items():
        user_watchlist = user_data.get('watchlist', [])
        user_alerts = price_alerts.get(username, {})
        watchlist_details = []

        for crypto_id in user_watchlist:
            alert_info = user_alerts.get(crypto_id, {})

            # Local DB coin
            if crypto_id in CRYPTO_DATABASE:
                crypto_info = CRYPTO_DATABASE[crypto_id]
                name = crypto_info.get("name", crypto_id)
                price = crypto_info.get("current_price", 0)

            # API coin
            else:
                api_data = get_crypto_details_by_id(crypto_id)
                name = crypto_id
                price = api_data.get("current_price", 0) if api_data else 0

            watchlist_details.append({
                'symbol': crypto_id,
                'name': name,
                'price': price,
                'has_alert': crypto_id in user_alerts,
                'alert_type': alert_info.get('alert_type', 'N/A'),
                'alert_price': alert_info.get('threshold_price', 0)
            })

        detailed_users.append({
            'username': username,
            'email': user_data.get('email', 'N/A'),
            'watchlist_count': len(user_watchlist),
            'alert_count': len(user_alerts),
            'watchlist': watchlist_details,
            'alerts': user_alerts
        })

    analytics = {
        'total_users': total_users,
        'total_watchlists': total_watchlists,
        'total_alerts': total_alerts,
        'top_cryptos': top_cryptos,
        'recent_alerts': recent_alerts[:10],
        'crypto_prices': [(crypto_id, data['current_price']) for crypto_id, data in CRYPTO_DATABASE.items()],
        'detailed_users': detailed_users
    }

    return render_template('admin_dashboard.html', analytics=analytics)


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('admin', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)

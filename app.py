from flask import Flask, render_template, redirect, url_for, request, session, flash
import sqlite3
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_oauthlib.client import OAuth
import os

secret_key = secrets.token_hex(16)
app = Flask(__name__)
app.secret_key = secret_key
oauth = OAuth(app)

# Retrieve sensitive information from environment variables
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')

# Use these variables in your application
print(f"Google Client ID: {GOOGLE_CLIENT_ID}")
print(f"Google Client Secret: {GOOGLE_CLIENT_SECRET}")
FACEBOOK_APP_ID = 'your-facebook-app-id'
FACEBOOK_APP_SECRET = 'your-facebook-app-secret'
LINKEDIN_CLIENT_ID = 'your-linkedin-client-id'
LINKEDIN_CLIENT_SECRET = 'your-linkedin-client-secret'

# Google OAuth configuration
google = oauth.remote_app(
    'google',
    consumer_key=GOOGLE_CLIENT_ID,
    consumer_secret=GOOGLE_CLIENT_SECRET,
    request_token_params={
        'scope': 'email profile'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

# Facebook OAuth configuration
facebook = oauth.remote_app(
    'facebook',
    consumer_key=FACEBOOK_APP_ID,
    consumer_secret=FACEBOOK_APP_SECRET,
    request_token_params={
        'scope': 'email'
    },
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth'
)

# LinkedIn OAuth configuration
linkedin = oauth.remote_app(
    'linkedin',
    consumer_key=LINKEDIN_CLIENT_ID,
    consumer_secret=LINKEDIN_CLIENT_SECRET,
    request_token_params={
        'scope': 'r_liteprofile r_emailaddress'
    },
    base_url='https://api.linkedin.com/v2/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
    authorize_url='https://www.linkedin.com/oauth/v2/authorization'
)

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def landing_page():
    return render_template('Bikey_landingpage.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        realname = request.form['name']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        conn = get_db_connection()
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))
        try:
            conn.execute('INSERT INTO users (username, password, realname) VALUES (?, ?, ?)', (username, hashed_password, realname))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/index')
def index():
    if 'user_id' not in session and 'oauth_user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

# Google routes
@app.route('/login/google')
def login_google():
    return google.authorize(callback=url_for('google_authorized', _external=True))

@app.route('/login/google/authorized')
def google_authorized():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )

    session['google_token'] = (response['access_token'], '')
    user_info = google.get('userinfo')
    session['oauth_user'] = user_info.data['email']
    return redirect(url_for('index'))

# Facebook routes
@app.route('/login/facebook')
def login_facebook():
    return facebook.authorize(callback=url_for('facebook_authorized', _external=True))

@app.route('/login/facebook/authorized')
def facebook_authorized():
    response = facebook.authorized_response()
    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )

    session['facebook_token'] = (response['access_token'], '')
    user_info = facebook.get('/me?fields=id,name,email')
    session['oauth_user'] = user_info.data['email']
    return redirect(url_for('index'))

# LinkedIn routes
@app.route('/login/linkedin')
def login_linkedin():
    return linkedin.authorize(callback=url_for('linkedin_authorized', _external=True))

@app.route('/login/linkedin/authorized')
def linkedin_authorized():
    response = linkedin.authorized_response()
    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )

    session['linkedin_token'] = (response['access_token'], '')
    user_info = linkedin.get('me')
    session['oauth_user'] = user_info.data['localizedFirstName'] + ' ' + user_info.data['localizedLastName']
    return redirect(url_for('index'))

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('facebook_token')

@linkedin.tokengetter
def get_linkedin_oauth_token():
    return session.get('linkedin_token')

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)

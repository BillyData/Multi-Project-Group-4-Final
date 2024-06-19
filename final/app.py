from flask import Flask, render_template, redirect, url_for, request, session, flash
import sqlite3
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
secret_key = secrets.token_hex(16)
app = Flask(__name__)
app.secret_key=secret_key

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# Route for the landing page
@app.route('/')
def landing_page():
    return render_template('Bikey_landingpage.html')

# Route for the login page
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

# Route for the register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        realname = request.form['name']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        conn = get_db_connection()
        if (password != confirm_password):
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

# Route for the index page (protected)
@app.route('/index')
def index():
    # You would typically check user authentication here
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
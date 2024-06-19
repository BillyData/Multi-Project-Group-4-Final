from flask import Flask, render_template, redirect, url_for, request

app = Flask(__name__)

# Route for the landing page
@app.route('/')
def landing_page():
    return render_template('Bikey_landingpage.html')

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login logic here
        return redirect(url_for('index'))
    return render_template('login.html')

# Route for the register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Handle registration logic here
        return redirect(url_for('login'))
    return render_template('register.html')

# Route for the index page (protected)
@app.route('/index')
def index():
    # You would typically check user authentication here
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)

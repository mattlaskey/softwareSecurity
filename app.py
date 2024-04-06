from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from markupsafe import escape
import sqlite3
import hashlib
import os
import re
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

def csrf_token_valid():
    token = session.pop('_csrf_token', None)
    return token and request.form.get('_csrf_token') == token

# Function to create database and table
def create_table():
    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL
        )
    ''')
    cursor.execute("SELECT COUNT(*) FROM products")
    count = cursor.fetchone()[0]

    if count == 0:
        products = [
            ("Hockey Stick", "A high-quality hockey stick for professional players.", 59.99),
            ("Helmet", "A protective helmet for hockey players.", 29.99),
            ("Skates", "Professional ice skates for speed and precision.", 99.99)
        ]

        for product in products:
            cursor.execute("INSERT INTO products (name, description, price) VALUES (?, ?, ?)", product)

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY,
            product_id INTEGER NOT NULL,
            user TEXT NOT NULL,
            rating INTEGER NOT NULL,
            comment TEXT NOT NULL,
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    ''')
    conn.commit()
    conn.close()

# Function to add a new user with hashed password and salt
def add_user(username, password):
    salt = os.urandom(16)  # Generate a random salt
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, password_hash.hex(), salt.hex()))
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


# Function to check if user exists
def user_exists(username):
    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

# Function to verify user credentials
def verify_user(username, password):
    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(user[3]), 100000)
        if password_hash.hex() == user[2]:
            return True
    return False

# Route for login page
@app.route('/', methods=['GET', 'POST'])
def login():
    session.clear()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if verify_user(username, password):
            user = get_user(username)
            session['user_id'] = user[0]
            session['username'] = username
            print("User details:", user)  # Debugging line
            print("User ID:", session['user_id'])  # Debugging line
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Invalid username or password')
    return render_template('login.html', error='', csrf_token=generate_csrf_token())

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You need to log in first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Route for home page (after login)
def load_reviews():
    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT reviews.*, products.name FROM reviews JOIN products ON reviews.product_id = products.id")
    reviews = cursor.fetchall()
    conn.close()
    return reviews

# Route for the home page
@app.route('/home')
@login_required
def home():
    reviews = load_reviews()
    user_id = session.get('user_id')
    return render_template('home.html', reviews=reviews,user_id=user_id)

def is_strong_password(password):

    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*]", password):
        return False
    return True

# Route for submitting a review
@app.route('/submit_review', methods=['POST'])
def submit_review():
    if 'username' not in session:
        flash('You need to be logged in to submit a review', 'error')
        return redirect(url_for('login'))
    user = session['username']
    rating = request.form['rating']
    comment = escape(request.form['comment'])
    product_id = request.form['product_id']  # Assuming product ID 1, replace with your actual product ID

    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    
    cursor.execute("INSERT INTO reviews (product_id, user, rating, comment) VALUES (?, ?, ?, ?)", (product_id, user, rating, comment))
    
    conn.commit()
    conn.close()

    flash('Review submitted successfully', 'success')
    return redirect(url_for('home'))

# Route for logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Route for registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if username already exists
        if user_exists(username):
            error = 'Username already exists'
        
        # Check if passwords match
        elif password != confirm_password:
            error = 'Password and confirm password do not match'
        
        # Check if password is strong enough
        elif not is_strong_password(password):
            error = 'Password is not strong enough. It must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.'

        else:
            # Add user to the database
            add_user(username, password)
            return redirect(url_for('login'))

    return render_template('register.html', error=error)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    error = None
    
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if new password matches the confirmation
        if new_password != confirm_password:
            error = 'New password and confirmation do not match'
        
        else:
            username = session['username']
            
            # Verify old password
            if not verify_user(username, old_password):
                error = 'Invalid old password'
            else:
                # Check if new password is strong enough
                if not is_strong_password(new_password):
                    error = 'New password is not strong enough. It must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.'

                else:
                    # Hash and salt the new password
                    salt = os.urandom(16)
                    new_password_hash = hashlib.pbkdf2_hmac('sha256', new_password.encode(), salt, 100000)

                    # Update password in the database
                    conn = sqlite3.connect('my_database.db')
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?", (new_password_hash.hex(), salt.hex(), username))
                    conn.commit()
                    conn.close()

                    flash('Password changed successfully', 'success')
                    return redirect(url_for('home'))

    return render_template('change_password.html', error=error)


@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    data = request.json
    product_id = data.get('product_id')
    quantity = int(data.get('quantity'))
    if product_id not in session:
        session[product_id] = 0
    session[product_id] += quantity
    
    return jsonify({'message': f'{quantity} units of product {product_id} added to cart'})


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    error = request.args.get('error')
    success_message = request.args.get('success_message')

    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name, price, id FROM products")
    products = cursor.fetchall()
    conn.close()

    cart_items = []
    for item in products:
        if str(item[2]) in session:
            name = item[0]
            unit_price = item[1]
            quantity = session[str(item[2])]
            total_price = unit_price * quantity
            cart_items.append({
                'name': name,
                'quantity': quantity,
                'unit_price': unit_price,
                'total_price': total_price
            })
    
    for item in cart_items:
        print("Name:", item['name'])
        print("Quantity:", item['quantity'])
        print("Unit Price:", item['unit_price'])
        print("Total Price:", item['total_price'])
        print()
    
    if error:
        return render_template('checkout.html', error=error)
    elif success_message:
        return render_template('checkout.html', success_message=success_message)
    return render_template('checkout.html', cart_items=cart_items)

def empty_cart():
    if "1" in session:
        session.pop("1")
    if "2" in session:
        session.pop("2")
    if "3" in session:
        session.pop("3")

@app.route('/empty_cart')
def empty_cart_endpoint():
    empty_cart()
    return redirect(url_for('checkout', success_message='Cart emptied successfully'))


@app.route('/purchase', methods=['POST'])
def purchase():
    if "1" not in session and "2" not in session and "3" not in session:
        error = 'cart is empty'
        return redirect(url_for('checkout',error=error))
    empty_cart()
    return redirect(url_for('success'))


@app.route('/success')
@login_required
def success():
    return render_template('success.html')




if __name__ == '__main__':
    create_table()
    app.run(debug=True)

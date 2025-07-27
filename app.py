from flask import Flask, request, redirect, render_template, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
csrf = CSRFProtect(app)

DATABASE = 'db.sqlite'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            balance INTEGER DEFAULT 1000,
            role TEXT DEFAULT 'user'
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            content TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM comments")
    comments = cur.fetchall()
    return render_template('index.html', comments=comments)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            flash("Registration successful. Please login.")
            return redirect('/login')
        except:
            flash("Username already exists.")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cur.fetchone()
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['user_id'] = user['id']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect('/admin')
            return redirect('/dashboard')
        else:
            flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT balance FROM users WHERE id=?", (session['user_id'],))
    balance = cur.fetchone()['balance']

    if request.method == 'POST':
        to_user = request.form['to']
        try:
            amount = int(request.form['amount'])
            if amount <= 0:
                flash("Invalid amount.")
                return redirect('/dashboard')

            # تحقق من رصيد المستخدم
            cur.execute("SELECT balance FROM users WHERE id=?", (session['user_id'],))
            current_balance = cur.fetchone()['balance']
            if current_balance < amount:
                flash("Insufficient balance.")
                return redirect('/dashboard')

            # تحقق من وجود المستلم
            cur.execute("SELECT id FROM users WHERE username=?", (to_user,))
            recipient = cur.fetchone()
            if not recipient:
                flash("Recipient not found.")
                return redirect('/dashboard')

            # تنفيذ التحويل
            cur.execute("UPDATE users SET balance = balance - ? WHERE id=?", (amount, session['user_id']))
            cur.execute("UPDATE users SET balance = balance + ? WHERE username=?", (amount, to_user))
            conn.commit()
            flash("Transfer successful.")
        except ValueError:
            flash("Invalid amount format.")
    return render_template('dashboard.html', username=session['username'], balance=balance)

@app.route('/comment', methods=['POST'])
@csrf.exempt  # يمكنك إزالته إذا استخدمت FlaskForm
def comment():
    if 'username' not in session:
        return redirect('/login')
    content = request.form['comment']
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (session['username'], content))
    conn.commit()
    return redirect('/')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect('/login')
    if request.method == 'POST':
        flash(f"Post received: {request.form['post']}")
    return render_template('admin.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=False)

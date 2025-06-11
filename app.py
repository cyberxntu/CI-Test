from flask import Flask, request, redirect, render_template, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'super_insecure_key'  

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
            balance INTEGER DEFAULT 1000
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
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except:
            return " اسم المستخدم موجود"
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cur.fetchone()
        if user:
            session['username'] = user['username']
            session['user_id'] = user['id']
            if username == 'admin':
                return redirect('/admin')
            return redirect('/dashboard')
        else:
            return " اسم المستخدم أو كلمة المرور غير صحيحة"
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
        amount = int(request.form['amount'])
        cur.execute("UPDATE users SET balance = balance - ? WHERE id=?", (amount, session['user_id']))
        cur.execute("UPDATE users SET balance = balance + ? WHERE username=?", (amount, to_user))
        conn.commit()
    return render_template('dashboard.html', username=session['username'], balance=balance)

@app.route('/comment', methods=['POST'])
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
    if 'username' not in session:
        return redirect('/login')
    if request.method == 'POST':
        return f"تم استقبال المنشور: {request.form['post']}"
    return render_template('admin.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)

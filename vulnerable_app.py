#!/usr/bin/env python3
# vulnerable_app.py
# A small vulnerable Flask app for demonstration

from flask import Flask, request, redirect, url_for, send_from_directory
import sqlite3
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['SECRET_KEY'] = 'hardcoded-secret'  # Hardcoded secret (vulnerability)
app.debug = True  # Debug mode enabled (vulnerability)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db():
    conn = sqlite3.connect('users.db')
    return conn

# Create table if not exists
conn = get_db()
conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()
conn.close()

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    # Insecure: storing plaintext password
    conn = get_db()
    sql = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
    conn.execute(sql)
    conn.commit()
    conn.close()
    return "Registered"

@app.route('/login', methods=['POST'])
def login():
    # Vulnerable to SQL injection
    username = request.form.get('username')
    password = request.form.get('password')
    conn = get_db()
    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
    cur = conn.execute(query)
    row = cur.fetchone()
    conn.close()
    if row:
        return f"Welcome {username}!"
    else:
        return "Login failed"

@app.route('/run', methods=['POST'])
def run():
    # Dangerous: using eval on user input
    code = request.form.get('code', '')
    result = eval(code)  # RCE vulnerability
    return f"Result: {result}"

@app.route('/upload', methods=['POST'])
def upload():
    # Insecure file upload: no validation, saving original filename
    f = request.files.get('file')
    if not f:
        return "No file"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
    f.save(filepath)
    return f"Saved {f.filename}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

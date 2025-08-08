#!/usr/bin/env python3
# secure_app.py
# Secure version: parameterized queries, password hashing, safe file upload, no eval, disabled debug

from flask import Flask, request, redirect, url_for, send_from_directory, abort
import sqlite3
import os
from werkzeug.utils import secure_filename
from bcrypt import gensalt, hashpw, checkpw

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024  # 4 MB limit
# Remove hardcoded secret; use environment variable (example)
app.config['SECRET_KEY'] = os.environ.get('APP_SECRET_KEY', None)
app.debug = False  # Do not run in debug mode for production

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db():
    conn = sqlite3.connect('users.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize DB (run once)
conn = get_db()
conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)")
conn.commit()
conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    if not username or not password:
        abort(400, "Missing username or password")
    # Hash password with bcrypt
    salt = gensalt()
    password_hash = hashpw(password.encode('utf-8'), salt)
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        abort(409, "User exists")
    conn.close()
    return "Registered", 201

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    if not username or not password:
        abort(400, "Missing credentials")
    conn = get_db()
    cur = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if row and checkpw(password.encode('utf-8'), row['password_hash']):
        return f"Welcome {username}!"
    return "Login failed", 401

@app.route('/evaluate', methods=['POST'])
def evaluate():
    # Do not eval arbitrary user input. Provide a limited, safe operation example instead.
    # Example: allow only a math expression with digits, + - * / and parentheses (basic validator)
    expr = request.form.get('expr', '')
    import re
    if not re.fullmatch(r'[\d\+\-\*\/\(\)\s\.]+', expr):
        abort(400, "Invalid expression")
    # Evaluate safely using ast.literal_eval on a parsed AST checked for allowed nodes (simple approach)
    import ast, operator
    # A safe eval implementation for basic arithmetic:
    def safe_eval(node):
        if isinstance(node, ast.Expression):
            return safe_eval(node.body)
        if isinstance(node, ast.BinOp):
            left = safe_eval(node.left); right = safe_eval(node.right)
            ops = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}
            op_type = type(node.op)
            if op_type in ops:
                return ops[op_type](left, right)
            else:
                raise ValueError("Unsupported operator")
        if isinstance(node, ast.Num):
            return node.n
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            val = safe_eval(node.operand)
            return +val if isinstance(node.op, ast.UAdd) else -val
        raise ValueError("Unsupported expression")
    parsed = ast.parse(expr, mode='eval')
    try:
        result = safe_eval(parsed)
    except Exception:
        abort(400, "Could not evaluate expression")
    return {"result": result}, 200

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('file')
    if not f:
        abort(400, "No file provided")
    filename = secure_filename(f.filename)
    if not filename:
        abort(400, "Invalid filename")
    if not allowed_file(filename):
        abort(400, "File type not allowed")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    f.save(filepath)
    # Optionally, verify magic bytes or mime type before serving
    return f"Saved {filename}", 201

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)

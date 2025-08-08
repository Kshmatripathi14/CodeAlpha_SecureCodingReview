## Project
- Sample vulnerable Python web app (`vulnerable_app.py`) and fixed version (`secure_app.py`).

---

## Summary of Findings
We reviewed `vulnerable_app.py` and found multiple security issues. Each issue below includes severity, location, explanation, and remediation.

---

### 1) Hardcoded secret / config
- **Severity:** Medium
- **Location:** `vulnerable_app.py` line with `app.config['SECRET_KEY'] = 'hardcoded-secret'`
- **Explanation:** Secrets in source code can be leaked (repo, backups).
- **Remediation:** Use environment variables or a secrets manager. Example: `os.environ.get('APP_SECRET_KEY')`.

---

### 2) Debug mode enabled
- **Severity:** High (in production)
- **Location:** `app.debug = True`
- **Explanation:** Debug exposes interactive console and stack traces which may allow RCE.
- **Remediation:** Disable debug in production. Set via environment variables.

---

### 3) Plaintext password storage
- **Severity:** High
- **Location:** `register` storing `password` directly into DB
- **Explanation:** If DB compromised, passwords are exposed.
- **Remediation:** Use strong hashing (bcrypt, Argon2) with salt.

---

### 4) SQL Injection (concatenated queries)
- **Severity:** High
- **Location:** `login` and `register` using f-strings to build SQL
- **Explanation:** User input not parameterized -> SQL injection risk.
- **Remediation:** Use parameterized queries, e.g. `conn.execute("SELECT ... WHERE username = ?", (username,))`.

---

### 5) Remote Code Execution via `eval`
- **Severity:** Critical
- **Location:** `run()` uses `eval(code)`
- **Explanation:** `eval` on untrusted input can execute arbitrary code.
- **Remediation:** Remove `eval`. Implement safe parsers or a restricted interpreter. Example uses AST-based safe arithmetic evaluator.

---

### 6) Insecure file upload (no validation)
- **Severity:** High
- **Location:** `upload` saves `f.filename` directly
- **Explanation:** Path traversal or uploading malicious files (webshells).
- **Remediation:** Use `werkzeug.utils.secure_filename`, validate allowed extensions, set upload size limits, verify content type.

---

### 7) Lack of input validation / insufficient error handling
- **Severity:** Medium
- **Location:** All endpoints (missing checks)
- **Remediation:** Validate inputs (lengths, patterns), handle exceptions, return appropriate HTTP status codes.

---

## Recommended Actions (summary)
1. Remove hardcoded secrets; use environment variables.
2. Disable Flask debug in production.
3. Hash passwords with bcrypt/argon2 and salt.
4. Use parameterized SQL queries always.
5. Remove `eval`; if evaluating expressions, implement strict whitelisting or an AST-based evaluator.
6. Sanitize file uploads (secure_filename, allowed file types, size limits).
7. Run static analysis (Bandit) and dependency checks (safety / pip-audit).
8. Add logging (not verbose) and monitor error logs for suspicious activity.

---

## Evidence & Reproduction Notes
- SQL injection example:
  - Request to `/login` with username: `admin' --` could bypass authentication if password logic is concatenated.
- RCE example:
  - POST to `/run` with payload `code: "__import__('os').system('ls')"` would execute `ls`.

---

## Fixed Code
See `secure_app.py` for secure implementations:
- Parameterized queries
- Bcrypt hashing
- Safe file upload
- AST-based arithmetic evaluator (instead of eval)
- Debug disabled and use of environment secret

---

## Tools used
- Manual code review
- Suggested scan commands:
  - `pip install bandit`
  - `bandit -r .`
  - `pip install pip-audit`
  - `pip-audit`

---

## Conclusion
The vulnerable app intentionally had common web vulnerabilities for learning. After applying the remediation above and adopting secure coding practices, the app is much safer for demonstration and learning purposes.

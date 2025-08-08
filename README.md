# CodeAlpha_SecureCodingReview

## Overview
This submission contains a vulnerable sample app and a secure refactor, with a full code review and remediation steps. Use for learning secure coding principles.

## Repo Contents
- `vulnerable_app.py` — intentionally vulnerable code (do NOT run on public network)
- `secure_app.py` — corrected secure implementation
- `CODE_REVIEW.md` — findings, severity, and fixes
- `README.md` — this file

## Setup (local/test only)
1. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install flask bcrypt werkzeug

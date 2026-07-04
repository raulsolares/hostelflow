#!/usr/bin/env python3
"""Quick verification: compile both .py files and test basic imports."""
import sys, py_compile, importlib

# Syntax check
for f in ["models.py", "main.py"]:
    path = f"/mnt/d/hermes/hostelflow/{f}"
    try:
        py_compile.compile(path, doraise=True)
        print(f"✅ {f} — syntax OK")
    except py_compile.PyCompileError as e:
        print(f"❌ {f} — {e}")
        sys.exit(1)

# Import check (models)
sys.path.insert(0, "/mnt/d/hermes/hostelflow")
from models import Base, User, Hotel, GuestLead, ContentModule, FAQItem, Promo, AccessLog, QRSource, UserRole
print("✅ models.py — all imports OK")

# Import check (main — needs fastapi, sqlalchemy, etc.)
try:
    import fastapi
    import sqlalchemy
    from jose import jwt
    from passlib.context import CryptContext
    import qrcode
    print(f"✅ Dependencies: fastapi={fastapi.__version__}, sqlalchemy={sqlalchemy.__version__}")
except ImportError as e:
    print(f"⚠️  Missing dependency: {e}")
    print("   Install with: pip install -r /mnt/d/hermes/hostelflow/requirements.txt")
    sys.exit(1)

# Compile main.py
try:
    py_compile.compile("/mnt/d/hermes/hostelflow/main.py", doraise=True)
    print("✅ main.py — compilation OK")
except py_compile.PyCompileError as e:
    print(f"❌ main.py — {e}")
    sys.exit(1)

print("\n🎉 All checks passed!")

"""
================================================================
 DecodeLabs Project 3 : ENTERPRISE RANDOM PASSWORD GENERATOR
 Single-file backend with all advanced features:

  ✅ Secure password generation (secrets module)
  ✅ Passphrase mode (Diceware-style)
  ✅ Exclude ambiguous characters (O, 0, l, 1, I)
  ✅ Ambiguous char filtering
  ✅ Password history (last 10)
  ✅ Entropy + crack time estimation
  ✅ Strength scoring breakdown
  ✅ HaveIBeenPwned breach check (k-anonymity)
  ✅ SQLite encrypted vault (Fernet)
  ✅ Bulk generation (up to 100 at once)
  ✅ CSV export
  ✅ Basic rate limiting
  ✅ Serves index.html from same folder
================================================================
"""

# ------------------------------------------------------------------
# Imports
# ------------------------------------------------------------------
from flask import Flask, request, jsonify, render_template, Response
from collections import deque, defaultdict
from time import time
import secrets
import string
import math
import os
import io
import csv
import sqlite3
import hashlib
import urllib.request
import urllib.error

# Optional: cryptography (for vault)
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("⚠  'cryptography' not installed — vault features disabled.")
    print("   Install with: pip install cryptography")

# ------------------------------------------------------------------
# Flask App Setup (serves index.html from same folder)
# ------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=BASE_DIR)

# ------------------------------------------------------------------
# Constants & Configuration
# ------------------------------------------------------------------
AMBIGUOUS_CHARS = set("O0oIl1|`'\",;:.")

# Compact Diceware-style wordlist (extend as needed)
WORDLIST = [
    "apple", "zebra", "piano", "tiger", "castle", "rocket", "sunset", "forest",
    "ocean", "mountain", "river", "silver", "golden", "thunder", "falcon", "phoenix",
    "dragon", "crystal", "shadow", "spark", "ember", "frost", "storm", "cloud",
    "planet", "comet", "galaxy", "meteor", "nebula", "cosmos", "orbit", "rocket",
    "garden", "meadow", "valley", "desert", "island", "harbor", "bridge", "tower",
    "candle", "lantern", "mirror", "feather", "pebble", "boulder", "canyon", "glacier",
    "velvet", "copper", "marble", "granite", "amber", "ivory", "pearl", "topaz",
    "winter", "summer", "autumn", "spring", "morning", "evening", "midnight", "twilight",
    "whisper", "echo", "silence", "harmony", "melody", "rhythm", "chorus", "anthem",
    "courage", "wisdom", "honor", "valor", "spirit", "dream", "vision", "purpose",
]

# Runtime state
password_history = deque(maxlen=10)       # last 10 generated passwords
request_log      = defaultdict(list)      # IP → list of timestamps
RATE_LIMIT       = 60                     # max requests per IP per minute

# ------------------------------------------------------------------
# Vault Setup (SQLite + Fernet encryption)
# ------------------------------------------------------------------
VAULT_DB    = os.path.join(BASE_DIR, "vault.db")
VAULT_KEY_F = os.path.join(BASE_DIR, "vault.key")
fernet      = None


def init_vault():
    """Initialize SQLite DB and Fernet key (auto-generated on first run)."""
    global fernet
    if not CRYPTO_AVAILABLE:
        return

    # Generate or load encryption key
    if os.path.exists(VAULT_KEY_F):
        with open(VAULT_KEY_F, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(VAULT_KEY_F, "wb") as f:
            f.write(key)

    fernet = Fernet(key)

    # Create table
    conn = sqlite3.connect(VAULT_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            encrypted_password BLOB NOT NULL,
            entropy REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def save_to_vault(label, password, entropy):
    """Encrypt and store a password in the vault."""
    if not fernet:
        raise RuntimeError("Vault not available. Install 'cryptography'.")
    enc = fernet.encrypt(password.encode())
    conn = sqlite3.connect(VAULT_DB)
    conn.execute(
        "INSERT INTO vault (label, encrypted_password, entropy) VALUES (?, ?, ?)",
        (label, enc, entropy)
    )
    conn.commit()
    conn.close()


def list_vault():
    """Return all decrypted vault entries."""
    if not fernet:
        return []
    conn = sqlite3.connect(VAULT_DB)
    rows = conn.execute(
        "SELECT id, label, encrypted_password, entropy, created_at FROM vault ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return [
        {
            "id": r[0],
            "label": r[1],
            "password": fernet.decrypt(r[2]).decode(),
            "entropy": r[3],
            "created_at": r[4],
        }
        for r in rows
    ]


def delete_from_vault(entry_id):
    conn = sqlite3.connect(VAULT_DB)
    conn.execute("DELETE FROM vault WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()


# ------------------------------------------------------------------
# Rate Limiting
# ------------------------------------------------------------------
def is_rate_limited(ip):
    """Allow RATE_LIMIT requests per IP per minute."""
    now = time()
    request_log[ip] = [t for t in request_log[ip] if now - t < 60]
    if len(request_log[ip]) >= RATE_LIMIT:
        return True
    request_log[ip].append(now)
    return False


# ------------------------------------------------------------------
# Character Pool Builder
# ------------------------------------------------------------------
def build_character_pool(include_digits=True,
                         include_symbols=True,
                         exclude_ambiguous=False):
    """Build the character pool from Python's string module constants."""
    pool = string.ascii_letters
    if include_digits:
        pool += string.digits
    if include_symbols:
        pool += string.punctuation
    if exclude_ambiguous:
        pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
    return pool


# ------------------------------------------------------------------
# Password & Passphrase Generation
# ------------------------------------------------------------------
def generate_password(length,
                      include_digits=True,
                      include_symbols=True,
                      exclude_ambiguous=False,
                      require_each_type=False):
    """
    Cryptographically secure password via secrets.choice().
    Uses ''.join() → O(N) linear time.
    """
    pool = build_character_pool(include_digits, include_symbols, exclude_ambiguous)

    if require_each_type:
        # Guarantee at least one of each required category
        required = []
        letters_pool = "".join(c for c in string.ascii_letters
                               if not exclude_ambiguous or c not in AMBIGUOUS_CHARS)
        required.append(secrets.choice(letters_pool))

        if include_digits:
            digits_pool = "".join(c for c in string.digits
                                  if not exclude_ambiguous or c not in AMBIGUOUS_CHARS)
            if digits_pool:
                required.append(secrets.choice(digits_pool))

        if include_symbols:
            symbols_pool = "".join(c for c in string.punctuation
                                   if not exclude_ambiguous or c not in AMBIGUOUS_CHARS)
            if symbols_pool:
                required.append(secrets.choice(symbols_pool))

        remaining = [secrets.choice(pool) for _ in range(length - len(required))]
        chars = required + remaining
        secrets.SystemRandom().shuffle(chars)   # secure shuffle
        return "".join(chars)

    return "".join(secrets.choice(pool) for _ in range(length))


def generate_passphrase(word_count=4, separator="-", capitalize=True, add_number=False):
    """Diceware-style memorable passphrase."""
    words = [secrets.choice(WORDLIST) for _ in range(word_count)]
    if capitalize:
        words = [w.capitalize() for w in words]
    phrase = separator.join(words)
    if add_number:
        phrase += str(secrets.randbelow(100))
    return phrase


# ------------------------------------------------------------------
# Entropy & Strength Scoring
# ------------------------------------------------------------------
def calculate_entropy(length, pool_size):
    """E = L × log₂(R)"""
    if pool_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(pool_size)


def classify_strength(entropy):
    if entropy < 40:
        return "Weak", "#e74c3c"
    elif entropy < 60:
        return "Moderate", "#f39c12"
    elif entropy < 80:
        return "Strong", "#2ecc71"
    else:
        return "Very Strong", "#27ae60"


def score_breakdown(length, entropy, include_digits, include_symbols):
    """Return a component-wise 0–100 score."""
    length_score = min(length * 4, 40)
    variety_score = (10 if include_digits else 0) + (15 if include_symbols else 0) + 15
    entropy_score = min(entropy * 0.3, 30)
    total = round(length_score + variety_score + entropy_score)
    return {
        "length_score":  round(length_score, 1),
        "variety_score": round(variety_score, 1),
        "entropy_score": round(entropy_score, 1),
        "total":         min(total, 100),
    }


def humanize_time(seconds):
    """Convert seconds to human-friendly string."""
    if seconds < 1:
        return "Instantly"
    units = [
        ("year",   60 * 60 * 24 * 365),
        ("day",    60 * 60 * 24),
        ("hour",   60 * 60),
        ("minute", 60),
        ("second", 1),
    ]
    for name, secs in units:
        if seconds >= secs:
            value = seconds / secs
            if value > 1e15:
                return "Billions of years"
            if value >= 1:
                return f"{value:,.0f} {name}{'s' if value >= 2 else ''}"
    return "Instantly"


# ------------------------------------------------------------------
# HaveIBeenPwned Breach Check (k-anonymity)
# ------------------------------------------------------------------
def is_compromised(password, timeout=4):
    """
    Check password against HIBP's pwned-passwords database.
    Only the first 5 chars of the SHA-1 hash leave the machine.
    Returns: (count, error)
    """
    sha1   = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url    = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DecodeLabs-P3"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            for line in r.read().decode().splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return int(count), None
        return 0, None
    except urllib.error.URLError as e:
        return 0, f"Network error: {e}"
    except Exception as e:
        return 0, f"Check failed: {e}"


# ------------------------------------------------------------------
# Routes — HTML
# ------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ------------------------------------------------------------------
# Routes — API
# ------------------------------------------------------------------
@app.route("/api/generate", methods=["POST"])
def api_generate():
    """Generate one password (or passphrase)."""
    ip = request.remote_addr or "unknown"
    if is_rate_limited(ip):
        return jsonify({"success": False,
                        "error": "Rate limit exceeded. Try again in a minute."}), 429

    try:
        data = request.get_json(silent=True) or {}

        mode = data.get("mode", "password").lower()

        # ---------- Passphrase mode ----------
        if mode == "passphrase":
            word_count = max(3, min(int(data.get("word_count", 4)), 8))
            separator  = str(data.get("separator", "-"))[:3] or "-"
            capitalize = bool(data.get("capitalize", True))
            add_number = bool(data.get("add_number", False))

            passphrase = generate_passphrase(word_count, separator, capitalize, add_number)
            pool_size  = len(WORDLIST)
            entropy    = round(calculate_entropy(word_count, pool_size), 2)
            label, color = classify_strength(entropy)

            record = {"password": passphrase, "entropy": entropy, "mode": "passphrase"}
            password_history.append(record)

            return jsonify({
                "success": True,
                "password": passphrase,
                "entropy_bits": entropy,
                "pool_size": pool_size,
                "strength": label,
                "strength_color": color,
                "crack_time": humanize_time(pool_size ** word_count / 1e10),
                "length": len(passphrase),
                "mode": "passphrase",
                "breakdown": score_breakdown(len(passphrase), entropy, False, False),
            })

        # ---------- Password mode ----------
        try:
            length = int(data.get("length", 16))
        except (ValueError, TypeError):
            return jsonify({"success": False,
                            "error": "Length must be a valid integer."}), 400

        if length < 8:
            return jsonify({"success": False,
                            "error": "NIST recommends a minimum of 8 characters."}), 400
        if length > 128:
            return jsonify({"success": False,
                            "error": "Length cannot exceed 128 characters."}), 400

        include_digits    = bool(data.get("include_digits", True))
        include_symbols   = bool(data.get("include_symbols", True))
        exclude_ambiguous = bool(data.get("exclude_ambiguous", False))
        require_each_type = bool(data.get("require_each_type", True))
        check_breach      = bool(data.get("check_breach", False))

        # Generate
        password = generate_password(
            length, include_digits, include_symbols,
            exclude_ambiguous, require_each_type
        )

        # Entropy / strength
        pool_size = len(build_character_pool(
            include_digits, include_symbols, exclude_ambiguous))
        entropy = round(calculate_entropy(length, pool_size), 2)
        label, color = classify_strength(entropy)

        # Crack time
        guesses = pool_size ** length
        crack_time = humanize_time(guesses / 1e10)

        # Optional: breach check
        breach_count = None
        breach_error = None
        if check_breach:
            breach_count, breach_error = is_compromised(password)

        # Store in history
        password_history.append({
            "password": password,
            "entropy": entropy,
            "mode": "password",
        })

        return jsonify({
            "success":         True,
            "password":        password,
            "entropy_bits":    entropy,
            "pool_size":       pool_size,
            "strength":        label,
            "strength_color":  color,
            "crack_time":      crack_time,
            "length":          length,
            "mode":            "password",
            "breakdown":       score_breakdown(length, entropy,
                                               include_digits, include_symbols),
            "breach_count":    breach_count,
            "breach_error":    breach_error,
        })

    except Exception as e:
        return jsonify({"success": False,
                        "error": f"Internal error: {str(e)}"}), 500


@app.route("/api/bulk", methods=["POST"])
def api_bulk():
    """Generate multiple passwords at once."""
    ip = request.remote_addr or "unknown"
    if is_rate_limited(ip):
        return jsonify({"success": False, "error": "Rate limit exceeded."}), 429

    try:
        data  = request.get_json(silent=True) or {}
        count = max(1, min(int(data.get("count", 10)), 100))
        length = max(8, min(int(data.get("length", 16)), 128))
        include_digits    = bool(data.get("include_digits", True))
        include_symbols   = bool(data.get("include_symbols", True))
        exclude_ambiguous = bool(data.get("exclude_ambiguous", False))

        passwords = [
            generate_password(length, include_digits, include_symbols, exclude_ambiguous)
            for _ in range(count)
        ]
        return jsonify({"success": True, "count": count, "passwords": passwords})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/history", methods=["GET"])
def api_history():
    """Return the last 10 generated passwords (in-memory)."""
    return jsonify({"success": True, "history": list(password_history)})


@app.route("/api/check-breach", methods=["POST"])
def api_check_breach():
    """Check a user-supplied password against HIBP."""
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    if not pw:
        return jsonify({"success": False, "error": "No password provided."}), 400
    count, err = is_compromised(pw)
    return jsonify({
        "success":      True,
        "compromised":  count > 0,
        "count":        count,
        "error":        err,
    })


# ---------- Vault endpoints ----------
@app.route("/api/vault", methods=["GET"])
def api_vault_list():
    try:
        return jsonify({"success": True, "entries": list_vault()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/vault", methods=["POST"])
def api_vault_save():
    try:
        data = request.get_json(silent=True) or {}
        label    = (data.get("label") or "Untitled").strip()[:60]
        password = data.get("password", "")
        entropy  = float(data.get("entropy", 0))
        if not password:
            return jsonify({"success": False, "error": "No password to save."}), 400
        save_to_vault(label, password, entropy)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/vault/<int:entry_id>", methods=["DELETE"])
def api_vault_delete(entry_id):
    try:
        delete_from_vault(entry_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ---------- Export endpoints ----------
@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Password", "Entropy (bits)", "Mode"])
    for item in password_history:
        writer.writerow([item["password"], item.get("entropy", 0), item.get("mode", "password")])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=passwords.csv"},
    )


@app.route("/api/export/json", methods=["GET"])
def export_json():
    return jsonify({"success": True, "history": list(password_history)})


# ------------------------------------------------------------------
# Bootstrap
# ------------------------------------------------------------------
init_vault()

if __name__ == "__main__":
    print("=" * 60)
    print("  DecodeLabs — Enterprise Password Generator (Full)")
    print("  Running at: http://127.0.0.1:5000")
    print(f"  Cryptography available: {CRYPTO_AVAILABLE}")
    print("=" * 60)
    app.run(debug=True, host="127.0.0.1", port=5000)
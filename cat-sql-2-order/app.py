from flask import Flask, request, render_template_string, session, redirect, url_for, jsonify
import sqlite3
import os
from hashlib import sha256
import re
import urllib.parse

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Flag is hidden in the database
FLAG = "CTF{m30w_m30w_sql_inj3ct10n_purr_f3ct}"

WAF_PREFIX_CHECK_LEN = 8192

WAF_BLOCK_PATTERNS = [
    r"'",        # single quote
    r";",        # semicolon
    r"--",       # SQL comment
    r"/\*",      # start C-style comment
    r"\*/",      # end C-style comment
    r"\bUNION\b",# UNION keyword
    r"\bSELECT\b",
    r"\bINSERT\b",
    r"\bUPDATE\b",
    r"\bDELETE\b",
    r"\bDROP\b",
    r"\bATTACK\b", # example of extra blocked word (optional)
]

WAF_COMPILED = re.compile("|".join(WAF_BLOCK_PATTERNS), re.IGNORECASE)

def waf_check(input_value):
    """
    Check the input against the WAF rules. Returns (passed: bool, message: str).
    IMPORTANT: This WAF only inspects the first WAF_PREFIX_CHECK_LEN bytes (intentional).
    This is the designed bypass for the CTF: place malicious payload after that prefix.
    """
    if input_value is None:
        return True, ""

    # Normalize to string
    if not isinstance(input_value, str):
        input_value = str(input_value)

    # Single URL-decode (simulate typical WAF behavior which decodes once)
    try:
        decoded_once = urllib.parse.unquote(input_value)
    except Exception:
        decoded_once = input_value

    # Only inspect the prefix (intentional flaw)
    # To simulate byte limit, encode to utf-8, slice, then decode back
    encoded = decoded_once.encode('utf-8')
    prefix_bytes = encoded[:WAF_PREFIX_CHECK_LEN]
    sample = prefix_bytes.decode('utf-8', 'ignore')

    if WAF_COMPILED.search(sample):
        return False, "AWS WAF blocked suspicious input."

    return True, ""

def init_db():
    conn = sqlite3.connect('cats.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, email TEXT)''')
    
    # Cats table - corrected to include image_url and fun_fact
    c.execute('''CREATE TABLE IF NOT EXISTS cats
                 (id INTEGER PRIMARY KEY, name TEXT, breed TEXT, age INTEGER, 
                  description TEXT, owner_id INTEGER, secret_notes TEXT, 
                  image_url TEXT, fun_fact TEXT)''')
    
    # Secret admin table with flag
    c.execute('''CREATE TABLE IF NOT EXISTS admin_secrets
                 (id INTEGER PRIMARY KEY, secret_key TEXT, secret_value TEXT)''')
    
    # Adoption requests (rabbit hole)
    c.execute('''CREATE TABLE IF NOT EXISTS adoption_requests
                 (id INTEGER PRIMARY KEY, user_id INTEGER, cat_id INTEGER, 
                  status TEXT, message TEXT)''')
    
    # Insert admin user
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', ?, 'admin', 'admin@catshel.ter')", 
              (sha256(b'super_secret_admin_pass_N0t_Gu3ssabl3!').hexdigest(),))
    
    # Insert regular user
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'catLover', ?, 'user', 'catlover@email.com')", 
              (sha256(b'ilovecats123').hexdigest(),))
    
    # Insert decoy user (rabbit hole)
    c.execute("INSERT OR IGNORE INTO users VALUES (3, 'moderator', ?, 'moderator', 'mod@catshel.ter')", 
              (sha256(b'modpass2024').hexdigest(),))
    
    # Insert some cats with image and fun fact
    cats_data = [
        (1, 'Whiskers', 'Tabby', 3, 'A friendly orange tabby who loves treats and sunbathing.', 2, 'Vaccine record: updated', 'https://www.placecats.com/neo/300/200', 'Loves to chase laser pointers for hours!'),
        (2, 'Shadow', 'Black Cat', 5, 'Mysterious and elegant, prefers quiet corners.', 2, 'Previous owner: unknown', 'https://www.placecats.com/neo_2/300/200', 'Believes he is a ninja at night.'),
        (3, 'Fluffy', 'Persian', 2, 'Very fluffy, needs grooming daily.', 1, 'CTF{Y0u_G0T_th3_FL4g?}', 'https://www.placecats.com/millie/300/150', 'Has won 3 local beauty contests!'),
        (4, 'Mittens', 'Siamese', 4, 'Talkative and affectionate, follows you everywhere.', 1, 'Medical history: clean', 'https://www.placecats.com/poppy/300/200', 'Can meow in 5 different tones.')
    ]
    c.executemany("INSERT OR IGNORE INTO cats VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", cats_data)
    
    # Insert flag in admin secrets
    c.execute("INSERT OR IGNORE INTO admin_secrets VALUES (1, 'flag', ?)", (FLAG,))
    c.execute("INSERT OR IGNORE INTO admin_secrets VALUES (2, 'backup_codes', 'BC-2847-KFLS-9923')")
    
    conn.commit()
    conn.close()

init_db()

HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>🐱 Purrfect Cat Shelter 🐱</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 900px;
            margin: 50px auto;
            background: #fff5e6;
        }
        .header {
            text-align: center;
            color: #ff6b35;
        }
        .cat-card {
            border: 2px solid #ff6b35;
            padding: 15px;
            margin: 15px;
            border-radius: 12px;
            background: white;
            display: inline-block;
            width: 260px;
            vertical-align: top;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .cat-card img {
            width: 100%;
            height: 180px;
            object-fit: cover;
            border-radius: 8px;
        }
        input, button {
            padding: 8px 12px;
            margin: 5px;
            font-size: 14px;
        }
        button {
            background: #ff6b35;
            color: white;
            border: none;
            cursor: pointer;
            border-radius: 6px;
            transition: background 0.3s ease;
        }
        button:hover {
            background: #ff8555;
        }
        .profile {
            background: #ffe4cc;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            text-align: center;
        }
        .profile a {
            text-decoration: none;
            margin: 0 5px;
        }
        .profile button {
            width: auto;
            display: inline-block;
            min-width: 120px;
        }
        .cat-card button {
            width: 120px;
            display: inline-block;
            margin-top: 5px;
        }
        .btn-knowmore {
            background: #4a90e2;
        }
        .btn-knowmore:hover {
            background: #357abd;
        }
        .hint {
            background: #fff;
            border-left: 4px solid #ff6b35;
            padding: 10px;
            margin: 10px 0;
            font-size: 12px;
            color: #666;
        }
        .success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🐱 Purrfect Cat Shelter 🐱</h1>
        <p>Find your purrfect companion!</p>
    </div>
    
    {% if 'user_id' in session %}
        <div class="profile">
            <h3>Welcome, {{ username }}! 👋</h3>
            <p>Role: {{ role }}</p>
            <a href="/logout"><button>Logout</button></a>
            <a href="/profile"><button>My Profile</button></a>
            <a href="/search"><button>🔍 Search Cats</button></a>
            {% if role == 'admin' or role == 'moderator' %}
            <a href="/admin-panel"><button>🔐 Admin Panel</button></a>
            {% endif %}
        </div>
        
        {% if success %}
        <div class="success">
            {{ success }}
        </div>
        {% endif %}
        
        <h2 style="text-align:center;">Available Cats for Adoption 🐈</h2>
        <div style="text-align:center;">
        {% for cat in cats %}
        <div class="cat-card">
            <img src="{{ cat[7] }}" alt="{{ cat[1] }}">
            <h3>{{ cat[1] }}</h3>
            <p><strong>Breed:</strong> {{ cat[2] }} | <strong>Age:</strong> {{ cat[3] }} years</p>
            <p style="font-size:14px; height:40px; overflow:hidden;">{{ cat[4] }}</p>
            <form action="/adopt/{{ cat[0] }}" method="POST" style="display:inline;">
                <button type="submit">Adopt Me 💕</button>
            </form>
            <a href="/cat/{{ cat[0] }}"><button class="btn-knowmore">Know More 🐾</button></a>
        </div>
        {% endfor %}
        </div>
        
        <div class="hint">
            💡 Tip: Click "Know More" to learn fun facts and see full details!
        </div>
    {% else %}
        <div style="text-align: center; padding: 50px;">
            <h2>Please login to view our cats! 🔒</h2>
            <a href="/login"><button>Login</button></a>
            <a href="/register"><button>Register</button></a>
            <div class="hint">
                <!-- Development note: Remember to remove debug endpoint /api/users before production -->
            </div>
        </div>
    {% endif %}
</body>
</html>
"""


# New: Cat Detail Page Template
CAT_DETAIL_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ cat[1] }} - Purrfect Cat Shelter</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 50px auto; background: #fff5e6; }
        .container { background: white; padding: 30px; border-radius: 15px; border: 2px solid #ff6b35; text-align: center; }
        .cat-img { width: 100%; max-width: 500px; height: auto; border-radius: 12px; margin: 20px 0; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        h1 { color: #ff6b35; }
        .info { font-size: 18px; margin: 15px 0; }
        .fun-fact { background: #ffe4cc; padding: 15px; border-radius: 10px; font-style: italic; margin: 20px 0; }
        button { padding: 12px 24px; background: #ff6b35; color: white; border: none; cursor: pointer; border-radius: 6px; font-size: 16px; }
        button:hover { background: #ff8555; }
        .back-btn { background: #4a90e2; margin-left: 10px; }
        .back-btn:hover { background: #357abd; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🐱 {{ cat[1] }}</h1>
        <img src="{{ cat[7] }}" alt="{{ cat[1] }}" class="cat-img">
        
        <div class="info">
            <p><strong>Breed:</strong> {{ cat[2] }}</p>
            <p><strong>Age:</strong> {{ cat[3] }} years</p>
            <p><strong>Description:</strong> {{ cat[4] }}</p>
        </div>

        <div class="fun-fact">
            <strong>🐾 Fun Fact:</strong> {{ cat[8] }}
        </div>

        <div style="margin-top: 30px;">
            <form action="/adopt/{{ cat[0] }}" method="POST" style="display:inline;">
                <button type="submit">Adopt {{ cat[1] }}! 💕</button>
            </form>
            <a href="/"><button class="back-btn">Back to Home</button></a>
        </div>
    </div>
</body>
</html>
"""

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login - Cat Shelter</title>
    <style>
        body { font-family: Arial; max-width: 400px; margin: 100px auto; background: #fff5e6; }
        .form-box { background: white; padding: 30px; border-radius: 10px; border: 2px solid #ff6b35; }
        input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #ff6b35; color: white; border: none; cursor: pointer; }
        .error { color: red; }
        h2 { color: #ff6b35; text-align: center; }
        .hint { font-size: 11px; color: #999; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="form-box">
        <h2>🐱 Login</h2>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <p style="text-align: center;"><a href="/register">Need an account? Register here</a></p>
        <p style="text-align: center;"><a href="/forgot-password">Forgot password?</a></p>
        <div class="hint">
            🔒 Your password is hashed with SHA-256 for security
        </div>
    </div>
</body>
</html>
"""

REGISTER_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Register - Cat Shelter</title>
    <style>
        body { font-family: Arial; max-width: 400px; margin: 100px auto; background: #fff5e6; }
        .form-box { background: white; padding: 30px; border-radius: 10px; border: 2px solid #ff6b35; }
        input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #ff6b35; color: white; border: none; cursor: pointer; }
        .error { color: red; }
        .success { color: green; }
        h2 { color: #ff6b35; text-align: center; }
        .validation { font-size: 12px; color: #666; margin-top: -5px; }
    </style>
    <script>
        function validateForm(event) {
            const username = document.querySelector('input[name="username"]').value;
            const email = document.querySelector('input[name="email"]').value;
            const password = document.querySelector('input[name="password"]').value;
            
            if (username.length > 20 || email.length > 20 || password.length > 20) {
                alert("Each field can be no more than 20 characters long!");
                event.preventDefault();
                return false;
            }
            return true;
        }
    </script>
</head>
<body>
    <div class="form-box">
        <h2>🐱 Register</h2>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        {% if success %}<p class="success">{{ success }}</p>{% endif %}
        <form method="POST" onsubmit="return validateForm(event)">
            <input type="text" name="username" placeholder="Username" required>
            <p class="validation">Max 20 characters.</p>
            <input type="email" name="email" placeholder="Email" required>
            <p class="validation">Max 20 characters.</p>
            <input type="password" name="password" placeholder="Password" required>
            <p class="validation">Max 20 characters.</p>
            <button type="submit">Register</button>
        </form>
        <p style="text-align: center;"><a href="/login">Already have an account? Login</a></p>
    </div>
</body>
</html>
"""


PROFILE_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Profile - Cat Shelter</title>
    <style>
        body { font-family: Arial; max-width: 600px; margin: 50px auto; background: #fff5e6; }
        .profile-box { background: white; padding: 30px; border-radius: 10px; border: 2px solid #ff6b35; }
        h2 { color: #ff6b35; }
        .info { margin: 20px 0; }
        button { padding: 10px 20px; background: #ff6b35; color: white; border: none; cursor: pointer; }
        .admin-panel { background: #ffe4cc; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="profile-box">
        <h2>👤 User Profile</h2>
        <div class="info">
            <p><strong>Username:</strong> {{ username }}</p>
            <p><strong>Email:</strong> {{ email }}</p>
            <p><strong>Role:</strong> {{ role }}</p>
            <p><strong>Account ID:</strong> {{ user_id }}</p>
        </div>
        
        {% if role == 'admin' %}
        <div class="admin-panel">
            <h3>🔐 Admin Panel</h3>
            <p>Secret Data:</p>
            <pre>{{ admin_data }}</pre>
        </div>
        {% elif role == 'moderator' %}
        <div class="admin-panel">
            <h3>⚙️ Moderator Panel</h3>
            <p>You have limited administrative privileges.</p>
            <p>You can view user reports but not system secrets.</p>
        </div>
        {% endif %}
        
        <a href="/"><button>Back to Home</button></a>
    </div>
</body>
</html>
"""

SEARCH_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Search Cats</title>
    <style>
        body { font-family: Arial; max-width: 600px; margin: 50px auto; background: #fff5e6; }
        .search-box { background: white; padding: 30px; border-radius: 10px; border: 2px solid #ff6b35; }
        input { width: 80%; padding: 10px; }
        button { padding: 10px 20px; background: #ff6b35; color: white; border: none; cursor: pointer; }
        .result { border: 1px solid #ccc; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .note { font-size: 12px; color: #666; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="search-box">
        <h2>🔍 Search Cats</h2>
        <form method="GET">
            <input type="text" name="q" placeholder="Search by name or breed..." value="{{ query }}">
            <button type="submit">Search</button>
        </form>
        
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        
        {% if results %}
            <h3>Results:</h3>
            {% for cat in results %}
            <div class="result">
                <strong>{{ cat[1] }}</strong> - {{ cat[2] }}, {{ cat[3] }} years old
                <p>{{ cat[4] }}</p>
                <a href="/cat/{{ cat[0] }}"><button style="margin-top:8px; background:#4a90e2; font-size:12px; padding:6px 12px;">Know More 🐾</button></a>
            </div>
            {% endfor %}
        {% elif query %}
            <p>No cats found matching "{{ query }}"</p>
        {% endif %}
        
        <div class="note">
            💡 Search uses parameterized queries for security!<br>
            Try searching for: Tabby, Persian, or any cat name
        </div>
        
        <a href="/"><button style="margin-top: 20px;">Back to Home</button></a>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    if 'user_id' not in session:
        return render_template_string(HOME_PAGE)
    
    conn = sqlite3.connect('cats.db')
    c = conn.cursor()
    c.execute("SELECT * FROM cats")
    cats = c.fetchall()
    
    c.execute("SELECT username, role FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    success_msg = request.args.get('success')
    return render_template_string(HOME_PAGE, cats=cats, username=user[0], role=user[1], success=success_msg)

# New Route: Individual Cat Page
@app.route('/cat/<int:cat_id>')
def cat_detail(cat_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('cats.db')
    c = conn.cursor()
    c.execute("SELECT * FROM cats WHERE id = ?", (cat_id,))
    cat = c.fetchone()
    conn.close()
    
    if not cat:
        return redirect(url_for('home', success="Cat not found!"))
    
    return render_template_string(CAT_DETAIL_PAGE, cat=cat)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = sha256(request.form['password'].encode()).hexdigest()
        
        conn = sqlite3.connect('cats.db')
        c = conn.cursor()
        c.execute("SELECT id, role FROM users WHERE username = ? AND password = ?", 
                  (username, password))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = username
            return redirect(url_for('home'))
        
        return render_template_string(LOGIN_PAGE, error="Invalid credentials!")
    
    return render_template_string(LOGIN_PAGE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = sha256(request.form['password'].encode()).hexdigest()

        # WAF check on the username (and optionally email)
        passed, msg = waf_check(username)
        if not passed:
            return "illegal characters", 500
        
        conn = sqlite3.connect('cats.db')
        c = conn.cursor()
        
        try:
            c.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, 'user', ?)", 
                      (username, password, email))
            conn.commit()
            conn.close()
            return render_template_string(REGISTER_PAGE, 
                                        success="Account created! Please login.")
        except sqlite3.IntegrityError:
            conn.close()
            return render_template_string(REGISTER_PAGE, 
                                        error="Username already exists!")
    
    return render_template_string(REGISTER_PAGE)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('cats.db')
    c = conn.cursor()
    
    username = session['username']

    # WAF check on username retrieved from session
    passed, msg = waf_check(username)
    if not passed:
        return "illegal characters", 500  

    query = f"SELECT id, username, role, email FROM users WHERE username = '{username}'"
    c.execute(query)
    user_data = c.fetchone()
    
    admin_data = ""
    if user_data and user_data[2] == 'admin':
        c.execute("SELECT secret_key, secret_value FROM admin_secrets")
        secrets = c.fetchall()
        admin_data = "\n".join([f"{s[0]}: {s[1]}" for s in secrets])
    
    conn.close()
    
    return render_template_string(PROFILE_PAGE, 
                                username=user_data[1] if user_data else "Unknown",
                                email=user_data[3] if user_data else "Unknown",
                                role=user_data[2] if user_data else "Unknown",
                                user_id=user_data[0] if user_data else "Unknown",
                                admin_data=admin_data)

@app.route('/search')
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    query = request.args.get('q', '')
    results = []

    # WAF check on search query
    passed, msg = waf_check(query)
    if not passed:
        return "illegal characters", 500

    if query:
        conn = sqlite3.connect('cats.db')
        c = conn.cursor()
        c.execute("SELECT * FROM cats WHERE name LIKE ? OR breed LIKE ?", 
                  (f"%{query}%", f"%{query}%"))
        results = c.fetchall()
        conn.close()
    
    return render_template_string(SEARCH_PAGE, query=query, results=results)

@app.route('/api/users')
def api_users():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    conn = sqlite3.connect('cats.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE role != 'admin'")
    users = c.fetchall()
    conn.close()
    
    return jsonify([{"id": u[0], "username": u[1], "role": u[2]} for u in users])

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        return render_template_string("""
        <html>
        <head><title>Password Reset</title></head>
        <body style="font-family: Arial; max-width: 400px; margin: 100px auto;">
            <h2>Password Reset</h2>
            <p>If an account exists with email {{ email }}, a reset link has been sent.</p>
            <p><a href="/login">Back to Login</a></p>
        </body>
        </html>
        """, email=email)
    
    return render_template_string("""
    <html>
    <head><title>Forgot Password</title></head>
    <body style="font-family: Arial; max-width: 400px; margin: 100px auto;">
        <h2>Forgot Password</h2>
        <form method="POST">
            <input type="email" name="email" placeholder="Enter your email" required style="width: 100%; padding: 10px;">
            <button type="submit" style="width: 100%; padding: 10px; margin-top: 10px;">Reset Password</button>
        </form>
        <p><a href="/login">Back to Login</a></p>
    </body>
    </html>
    """)

@app.route('/admin-panel')
def admin_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('cats.db')
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    if not user or user[0] not in ['admin', 'moderator']:
        return "Access Denied: Admin or Moderator role required", 403
    
    if user[0] == 'moderator':
        return render_template_string("""
        <html>
        <body style="font-family: Arial; max-width: 600px; margin: 50px auto;">
            <h2>Moderator Panel</h2>
            <p>You have limited access. Only admins can view system secrets.</p>
            <a href="/"><button>Back to Home</button></a>
        </body>
        </html>
        """)
    
    return redirect(url_for('profile'))

@app.route('/adopt/<int:cat_id>', methods=['POST'])
def adopt(cat_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('cats.db')
    c = conn.cursor()
    
    c.execute("SELECT name FROM cats WHERE id = ?", (cat_id,))
    cat = c.fetchone()
    
    if cat:
        c.execute("INSERT INTO adoption_requests (user_id, cat_id, status, message) VALUES (?, ?, 'pending', 'Adoption request submitted')",
                  (session['user_id'], cat_id))
        conn.commit()
        conn.close()
        
        return redirect(url_for('home', success=f"🎉 Adoption request submitted for {cat[0]}! We'll contact you soon."))
    
    conn.close()
    return redirect(url_for('home', success="❌ Cat not found."))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.after_request
def add_aws_headers(response):
    response.headers['X-Amzn-RequestId'] = os.urandom(16).hex()
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=6767)
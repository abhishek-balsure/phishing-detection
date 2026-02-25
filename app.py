"""
Phishing Detection Web Application
A comprehensive Flask-based web application for detecting phishing URLs,
scanning emails and QR codes for malicious content.
"""

import os
import re
import sqlite3
import pickle
import base64
import io
import csv
import json
import logging
import math
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse, urljoin
from collections import Counter

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, g, session, send_file, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import pandas as pd
import numpy as np

# Import local feature extraction module
from feature_extraction import extract_features, features_to_array, get_feature_names

# Try to import optional dependencies
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    from PIL import Image
    from pyzbar.pyzbar import decode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'phishing_detection.db')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Load the phishing detection model
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
model = None
scaler = None

# Feature names expected by the model
MODEL_FEATURES = [
    'url_length', 'hostname_length', 'has_https', 'has_ip', 'num_dots',
    'num_hyphens', 'num_underscores', 'num_slashes', 'num_questionmarks',
    'num_at', 'num_digits', 'num_subdomains', 'has_prefix_suffix',
    'suspicious_tld', 'has_suspicious_keywords', 'is_shortened', 'url_entropy',
    'digit_ratio', 'special_char_ratio', 'path_length', 'query_length',
    'num_equals', 'num_ampersands', 'has_port', 'brand_in_subdomain'
]

try:
    with open(MODEL_PATH, 'rb') as f:
        model_data = pickle.load(f)
        # Handle both direct model and dict with model/scaler
        if isinstance(model_data, dict):
            model = model_data.get('model')
            scaler = model_data.get('scaler')
        else:
            model = model_data
            scaler = None
    logger.info(f"Phishing detection model loaded successfully. Type: {type(model)}")
except FileNotFoundError:
    logger.warning("Model file not found. Predictions will not be available.")
except Exception as e:
    logger.error(f"Error loading model: {e}")

# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================

def get_db():
    """Get database connection."""
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    """Close database connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


@app.teardown_appcontext
def close_connection(exception):
    """Close database connection after request."""
    close_db(exception)


def init_db():
    """Initialize the database with required tables."""
    db = get_db()
    
    # Users table
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Scans table
    db.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            confidence REAL,
            features TEXT,
            scan_type TEXT DEFAULT 'single',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Email scans table
    db.execute('''
        CREATE TABLE IF NOT EXISTS email_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            sender TEXT,
            subject TEXT,
            content TEXT,
            urls_found TEXT,
            malicious_urls INTEGER DEFAULT 0,
            scan_result TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # QR scans table
    db.execute('''
        CREATE TABLE IF NOT EXISTS qr_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            qr_data TEXT NOT NULL,
            is_url INTEGER DEFAULT 0,
            url_result TEXT,
            confidence REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Batch scans table
    db.execute('''
        CREATE TABLE IF NOT EXISTS batch_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            total_urls INTEGER,
            malicious_count INTEGER,
            safe_count INTEGER,
            file_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Bookmarks table
    db.execute('''
        CREATE TABLE IF NOT EXISTS bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            result TEXT,
            confidence REAL,
            note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create default admin user
    admin_hash = generate_password_hash('admin123')
    db.execute('''
        INSERT OR IGNORE INTO users (username, email, password, is_admin)
        VALUES (?, ?, ?, ?)
    ''', ('admin', 'admin@phishingdetection.com', admin_hash, 1))
    
    db.commit()
    logger.info("Database initialized successfully")


# Initialize database on startup
with app.app_context():
    init_db()


# ============================================================================
# DECORATORS
# ============================================================================

def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin privileges for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        db = get_db()
        user = db.execute(
            'SELECT is_admin FROM users WHERE id = ?', 
            (session['user_id'],)
        ).fetchone()
        
        if not user or not user['is_admin']:
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def extract_features_for_model(url):
    """
    Extract features from URL and return as numpy array for model prediction.
    """
    if not url:
        return np.zeros(len(MODEL_FEATURES))
    
    url = url.lower().strip()
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    
    features = {}
    
    # 1. URL length
    features['url_length'] = len(url)
    
    # 2. Hostname length
    features['hostname_length'] = len(hostname)
    
    # 3. Has HTTPS
    features['has_https'] = 1 if parsed.scheme == 'https' else 0
    
    # 4. Has IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$|(\d{1,3}\.){3}\d{1,3}(/|:)'
    features['has_ip'] = 1 if re.search(ip_pattern, hostname) else 0
    
    # 5. Number of dots
    features['num_dots'] = url.count('.')
    
    # 6. Number of hyphens
    features['num_hyphens'] = url.count('-')
    
    # 7. Number of underscores
    features['num_underscores'] = url.count('_')
    
    # 8. Number of slashes
    features['num_slashes'] = url.count('/')
    
    # 9. Number of question marks
    features['num_questionmarks'] = url.count('?')
    
    # 10. Number of @ symbols
    features['num_at'] = url.count('@')
    
    # 11. Number of digits
    features['num_digits'] = sum(c.isdigit() for c in url)
    
    # 12. Number of subdomains
    if hostname:
        domain_parts = hostname.split('.')
        if len(domain_parts) > 2:
            features['num_subdomains'] = len(domain_parts) - 2
        else:
            features['num_subdomains'] = 0
    else:
        features['num_subdomains'] = 0
    
    # 13. Has prefix-suffix (hyphen in domain)
    features['has_prefix_suffix'] = 1 if '-' in hostname else 0
    
    # 14. Suspicious TLD
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.buzz']
    features['suspicious_tld'] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0
    
    # 15. Has suspicious keywords
    suspicious_keywords = ['verify', 'account', 'login', 'secure', 'update', 'confirm', 
                          'banking', 'password', 'credential', 'wallet', 'payment']
    features['has_suspicious_keywords'] = 1 if any(keyword in url for keyword in suspicious_keywords) else 0
    
    # 16. Is shortened URL
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link', 
                  'is.gd', 'buff.ly', 'adf.ly', 'bitly.com']
    features['is_shortened'] = 1 if any(shortener in hostname for shortener in shorteners) else 0
    
    # 17. URL entropy (Shannon entropy)
    if url:
        prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        features['url_entropy'] = entropy
    else:
        features['url_entropy'] = 0.0
    
    # 18. Digit ratio
    features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0
    
    # 19. Special character ratio
    special_chars = sum(1 for c in url if not c.isalnum())
    features['special_char_ratio'] = special_chars / len(url) if len(url) > 0 else 0
    
    # 20. Path length
    features['path_length'] = len(path)
    
    # 21. Query length
    features['query_length'] = len(parsed.query)
    
    # 22. Number of equals signs
    features['num_equals'] = url.count('=')
    
    # 23. Number of ampersands
    features['num_ampersands'] = url.count('&')
    
    # 24. Has port number
    features['has_port'] = 1 if ':' in hostname and not hostname.endswith(':') else 0
    
    # 25. Brand name in subdomain (potential phishing)
    brands = ['paypal', 'apple', 'microsoft', 'google', 'facebook', 'amazon', 'netflix',
              'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard']
    subdomain = '.'.join(hostname.split('.')[:-2]) if len(hostname.split('.')) > 2 else ""
    features['brand_in_subdomain'] = 1 if any(brand in subdomain for brand in brands) else 0
    
    # Convert to array in correct order
    feature_array = [features.get(f, 0) for f in MODEL_FEATURES]
    return np.array(feature_array), features


def predict_url(url):
    """
    Predict if a URL is phishing or legitimate.
    
    Args:
        url (str): URL to analyze
        
    Returns:
        dict: Prediction results with confidence score and features
    """
    if model is None:
        return {
            'error': 'Model not loaded',
            'result': 'unknown',
            'confidence': 0.0,
            'features': {},
            'is_phishing': False,
            'is_legitimate': False
        }
    
    try:
        # Extract features
        feature_array, features_dict = extract_features_for_model(url)
        feature_array = feature_array.reshape(1, -1)
        
        # Scale features if scaler is available
        if scaler:
            feature_array = scaler.transform(feature_array)
        
        # Make prediction
        prediction = model.predict(feature_array)[0]
        
        # Get prediction probabilities if available
        try:
            probabilities = model.predict_proba(feature_array)[0]
            confidence = float(max(probabilities))
            prob_phishing = float(probabilities[1])
            prob_legitimate = float(probabilities[0])
        except:
            # Fallback if predict_proba is not available
            confidence = 0.85 if prediction == 1 else 0.85
            prob_phishing = 1.0 if prediction == 1 else 0.0
            prob_legitimate = 0.0 if prediction == 1 else 1.0
        
        # Map prediction to result (0 = legitimate, 1 = phishing)
        result = 'phishing' if prediction == 1 else 'legitimate'
        
        return {
            'result': result,
            'confidence': round(confidence * 100, 2),
            'features': features_dict,
            'is_phishing': prediction == 1,
            'is_legitimate': prediction == 0,
            'probability_phishing': round(prob_phishing * 100, 2),
            'probability_legitimate': round(prob_legitimate * 100, 2)
        }
    except Exception as e:
        logger.error(f"Error predicting URL {url}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            'error': str(e),
            'result': 'error',
            'confidence': 0.0,
            'features': {},
            'is_phishing': False,
            'is_legitimate': False
        }


def save_scan(user_id, url, result_data, scan_type='single'):
    """
    Save scan result to database.
    """
    try:
        db = get_db()
        db.execute('''
            INSERT INTO scans (user_id, url, result, confidence, features, scan_type)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user_id,
            url,
            result_data.get('result', 'unknown'),
            result_data.get('confidence', 0.0),
            json.dumps(result_data.get('features', {})),
            scan_type
        ))
        db.commit()
    except Exception as e:
        logger.error(f"Error saving scan: {e}")


def get_user_stats(user_id):
    """
    Get statistics for a user.
    """
    db = get_db()
    
    total_scans = db.execute(
        'SELECT COUNT(*) as count FROM scans WHERE user_id = ?',
        (user_id,)
    ).fetchone()['count']
    
    phishing_count = db.execute(
        "SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND result = 'phishing'",
        (user_id,)
    ).fetchone()['count']
    
    safe_count = db.execute(
        "SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND result = 'legitimate'",
        (user_id,)
    ).fetchone()['count']
    
    email_scans = db.execute(
        'SELECT COUNT(*) as count FROM email_scans WHERE user_id = ?',
        (user_id,)
    ).fetchone()['count']
    
    qr_scans = db.execute(
        'SELECT COUNT(*) as count FROM qr_scans WHERE user_id = ?',
        (user_id,)
    ).fetchone()['count']
    
    return {
        'total_scans': total_scans,
        'phishing_count': phishing_count,
        'safe_count': safe_count,
        'email_scans': email_scans,
        'qr_scans': qr_scans
    }


def extract_urls_from_text(text):
    """
    Extract URLs from text content.
    """
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return url_pattern.findall(text)


# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    """Home page."""
    db = get_db()
    
    # Get stats for homepage
    total_scans = db.execute('SELECT COUNT(*) as count FROM scans').fetchone()['count']
    total_users = db.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    phishing_detected = db.execute(
        "SELECT COUNT(*) as count FROM scans WHERE result = 'phishing'"
    ).fetchone()['count']
    
    return render_template(
        'index.html',
        total_scans=total_scans,
        total_users=total_users,
        phishing_detected=phishing_detected
    )


@app.route('/quick_check', methods=['POST'])
def quick_check():
    """Quick URL check from homepage."""
    url = request.form.get('url', '').strip()
    
    if not url:
        flash('Please enter a URL.', 'warning')
        return redirect(url_for('index'))
    
    if not url.startswith(('http://', 'https://')):
        flash('Please enter a valid URL starting with http:// or https://', 'warning')
        return redirect(url_for('index'))
    
    result = predict_url(url)
    
    # If user is logged in, save the scan
    if 'user_id' in session:
        save_scan(session['user_id'], url, result, 'quick')
    
    return render_template('check_url.html', result=result, url=url, quick_check=True)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password.', 'danger')
            return render_template('login.html')
        
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            
            # Update last login
            db.execute(
                'UPDATE users SET last_login = ? WHERE id = ?',
                (datetime.now(), user['id'])
            )
            db.commit()
            
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or not email or not password:
            flash('Please fill in all fields.', 'danger')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('signup.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('signup.html')
        
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Please enter a valid email address.', 'danger')
            return render_template('signup.html')
        
        db = get_db()
        
        # Check if username exists
        if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            flash('Username already taken.', 'danger')
            return render_template('signup.html')
        
        # Check if email exists
        if db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone():
            flash('Email already registered.', 'danger')
            return render_template('signup.html')
        
        # Create user
        password_hash = generate_password_hash(password)
        db.execute('''
            INSERT INTO users (username, email, password)
            VALUES (?, ?, ?)
        ''', (username, email, password_hash))
        db.commit()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')


@app.route('/logout')
def logout():
    """User logout."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard."""
    stats = get_user_stats(session['user_id'])
    
    db = get_db()
    recent_scans = db.execute('''
        SELECT * FROM scans 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 10
    ''', (session['user_id'],)).fetchall()
    
    recent_bookmarks = db.execute('''
        SELECT * FROM bookmarks 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 5
    ''', (session['user_id'],)).fetchall()
    
    return render_template(
        'dashboard.html',
        stats=stats,
        recent_scans=recent_scans,
        recent_bookmarks=recent_bookmarks,
        username=session.get('username')
    )


@app.route('/check_url', methods=['GET', 'POST'])
@login_required
def check_url():
    """URL checking page."""
    result = None
    url = ''
    
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        
        if not url:
            flash('Please enter a URL.', 'warning')
        elif not url.startswith(('http://', 'https://')):
            flash('Please enter a valid URL starting with http:// or https://', 'warning')
        else:
            result = predict_url(url)
            save_scan(session['user_id'], url, result, 'single')
    
    return render_template('check_url.html', result=result, url=url)


@app.route('/scanner')
@login_required
def scanner():
    """Unified scanner page with all scan types."""
    return render_template('scanner.html')


@app.route('/batch_check', methods=['GET', 'POST'])
@login_required
def batch_check():
    """Batch URL checking."""
    results = []
    
    if request.method == 'POST':
        urls_text = request.form.get('urls', '')
        file = request.files.get('file')
        
        urls = []
        
        # Get URLs from text area
        if urls_text:
            urls = [url.strip() for url in urls_text.split('\n') if url.strip()]
        
        # Get URLs from file
        if file and file.filename:
            try:
                filename = secure_filename(file.filename)
                if filename.endswith('.csv'):
                    # Read CSV file
                    file_content = file.read()
                    if isinstance(file_content, bytes):
                        file_content = file_content.decode('utf-8')
                    df = pd.read_csv(io.StringIO(file_content))
                    if 'url' in df.columns:
                        urls.extend(df['url'].dropna().astype(str).tolist())
                    else:
                        urls.extend(df.iloc[:, 0].dropna().astype(str).tolist())
                elif filename.endswith('.txt'):
                    content = file.read()
                    if isinstance(content, bytes):
                        content = content.decode('utf-8')
                    urls.extend([url.strip() for url in content.split('\n') if url.strip()])
            except Exception as e:
                flash(f'Error reading file: {e}', 'danger')
        
        if not urls:
            flash('Please enter URLs or upload a file.', 'warning')
        else:
            # Process URLs
            for url in urls[:100]:  # Limit to 100 URLs
                if url.startswith(('http://', 'https://')):
                    result = predict_url(url)
                    result['url'] = url
                    results.append(result)
                    save_scan(session['user_id'], url, result, 'batch')
            
            # Save batch scan summary
            malicious_count = sum(1 for r in results if r.get('result') == 'phishing')
            safe_count = sum(1 for r in results if r.get('result') == 'legitimate')
            
            db = get_db()
            db.execute('''
                INSERT INTO batch_scans (user_id, total_urls, malicious_count, safe_count)
                VALUES (?, ?, ?, ?)
            ''', (session['user_id'], len(results), malicious_count, safe_count))
            db.commit()
            
            return render_template(
                'batch_results.html',
                results=results,
                total=len(results),
                malicious=malicious_count,
                safe=safe_count
            )
    
    return render_template('batch.html')


@app.route('/email_scanner', methods=['GET', 'POST'])
@login_required
def email_scanner():
    """Email content scanner."""
    result = None
    
    if request.method == 'POST':
        sender = request.form.get('sender', '').strip()
        subject = request.form.get('subject', '').strip()
        content = request.form.get('content', '').strip()
        
        if not content:
            flash('Please enter email content.', 'warning')
        else:
            # Extract URLs from content
            urls = extract_urls_from_text(content)
            
            malicious_urls = 0
            url_results = []
            
            for url in urls[:20]:  # Limit to 20 URLs
                prediction = predict_url(url)
                url_results.append({
                    'url': url,
                    'result': prediction.get('result'),
                    'confidence': prediction.get('confidence')
                })
                if prediction.get('result') == 'phishing':
                    malicious_urls += 1
            
            # Determine overall result
            if malicious_urls > 0:
                overall_result = 'suspicious'
            elif len(urls) > 0:
                overall_result = 'safe'
            else:
                overall_result = 'no_urls'
            
            result = {
                'urls_found': len(urls),
                'malicious_urls': malicious_urls,
                'url_results': url_results,
                'overall_result': overall_result
            }
            
            # Save to database
            db = get_db()
            db.execute('''
                INSERT INTO email_scans 
                (user_id, sender, subject, content, urls_found, malicious_urls, scan_result)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                session['user_id'],
                sender,
                subject,
                content,
                json.dumps(urls),
                malicious_urls,
                overall_result
            ))
            db.commit()
    
    return render_template('email_scanner.html', result=result)


@app.route('/qr_scanner', methods=['GET', 'POST'])
@login_required
def qr_scanner():
    """QR code scanner."""
    result = None
    
    if request.method == 'POST':
        if 'qr_image' not in request.files:
            flash('No file uploaded.', 'warning')
            return render_template('qr_scanner.html')
        
        file = request.files['qr_image']
        
        if file.filename == '':
            flash('No file selected.', 'warning')
            return render_template('qr_scanner.html')
        
        if not QRCODE_AVAILABLE:
            flash('QR code scanning is not available. Please install required dependencies (Pillow, pyzbar).', 'danger')
            return render_template('qr_scanner.html')
        
        try:
            # Read image
            image = Image.open(file.stream)
            decoded_objects = decode(image)
            
            if not decoded_objects:
                flash('No QR code found in the image.', 'warning')
                return render_template('qr_scanner.html')
            
            qr_data = decoded_objects[0].data.decode('utf-8')
            
            # Check if QR data is a URL
            is_url = qr_data.startswith(('http://', 'https://'))
            
            url_result = None
            confidence = None
            
            if is_url:
                prediction = predict_url(qr_data)
                url_result = prediction.get('result')
                confidence = prediction.get('confidence')
            
            result = {
                'qr_data': qr_data,
                'is_url': is_url,
                'url_result': url_result,
                'confidence': confidence
            }
            
            # Save to database
            db = get_db()
            db.execute('''
                INSERT INTO qr_scans 
                (user_id, qr_data, is_url, url_result, confidence)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                session['user_id'],
                qr_data,
                int(is_url),
                url_result,
                confidence
            ))
            db.commit()
            
        except Exception as e:
            logger.error(f"Error processing QR code: {e}")
            flash(f'Error processing image: {e}', 'danger')
    
    return render_template('qr_scanner.html', result=result)


@app.route('/history')
@login_required
def history():
    """View scan history."""
    db = get_db()
    
    # Get query parameters for filtering
    search = request.args.get('search', '')
    filter_type = request.args.get('filter', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Build query
    query = 'SELECT * FROM scans WHERE user_id = ?'
    params = [session['user_id']]
    
    if search:
        query += ' AND url LIKE ?'
        params.append(f'%{search}%')
    
    if filter_type == 'phishing':
        query += " AND result = 'phishing'"
    elif filter_type == 'legitimate':
        query += " AND result = 'legitimate'"
    
    # Get total count
    count_query = query.replace('SELECT *', 'SELECT COUNT(*) as count')
    total = db.execute(count_query, params).fetchone()['count']
    
    # Add ordering and pagination
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
    params.extend([per_page, (page - 1) * per_page])
    
    scans = db.execute(query, params).fetchall()
    
    # Calculate total pages
    total_pages = (total + per_page - 1) // per_page
    
    return render_template(
        'history.html',
        scans=scans,
        search=search,
        filter_type=filter_type,
        page=page,
        total_pages=total_pages,
        total=total
    )


@app.route('/history/export/csv')
@login_required
def export_history_csv():
    """Export scan history as CSV."""
    db = get_db()
    scans = db.execute('''
        SELECT url, result, confidence, scan_type, created_at 
        FROM scans 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['URL', 'Result', 'Confidence (%)', 'Scan Type', 'Date'])
    
    for scan in scans:
        writer.writerow([
            scan['url'],
            scan['result'],
            f"{scan['confidence']:.2f}",
            scan['scan_type'],
            scan['created_at']
        ])
    
    output.seek(0)
    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=scan_history.csv'}
    )


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile and settings."""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    stats = get_user_stats(session['user_id'])
    
    recent_bookmarks = db.execute('''
        SELECT * FROM bookmarks 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 10
    ''', (session['user_id'],)).fetchall()
    
    recent_scans = db.execute('''
        SELECT * FROM scans 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 10
    ''', (session['user_id'],)).fetchall()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            
            if username and email:
                if username != user['username']:
                    if db.execute('SELECT id FROM users WHERE username = ? AND id != ?', (username, session['user_id'])).fetchone():
                        flash('Username already taken.', 'danger')
                        return render_template('profile.html', user=user)
                
                if email != user['email']:
                    if db.execute('SELECT id FROM users WHERE email = ? AND id != ?', (email, session['user_id'])).fetchone():
                        flash('Email already registered.', 'danger')
                        return render_template('profile.html', user=user)
                
                db.execute('UPDATE users SET username = ?, email = ? WHERE id = ?', 
                           (username, email, session['user_id']))
                db.commit()
                session['username'] = username
                flash('Profile updated successfully!', 'success')
                user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not check_password_hash(user['password'], current_password):
                flash('Current password is incorrect.', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
            elif len(new_password) < 8:
                flash('Password must be at least 8 characters.', 'danger')
            else:
                password_hash = generate_password_hash(new_password)
                db.execute('UPDATE users SET password = ? WHERE id = ?', (password_hash, session['user_id']))
                db.commit()
                flash('Password changed successfully!', 'success')
        
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    return render_template('profile.html', user=user, stats=stats, recent_bookmarks=recent_bookmarks, recent_scans=recent_scans)


@app.route('/bookmarks')
@login_required
def bookmarks():
    """View bookmarked URLs."""
    db = get_db()
    search = request.args.get('search', '')
    filter_type = request.args.get('filter', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = 15
    
    query = 'SELECT * FROM bookmarks WHERE user_id = ?'
    params = [session['user_id']]
    
    if search:
        query += ' AND url LIKE ?'
        params.append(f'%{search}%')
    
    if filter_type == 'phishing':
        query += " AND result = 'phishing'"
    elif filter_type == 'legitimate':
        query += " AND result = 'legitimate'"
    
    count_query = query.replace('SELECT *', 'SELECT COUNT(*) as count')
    total = db.execute(count_query, params).fetchone()['count']
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
    params.extend([per_page, (page - 1) * per_page])
    
    bookmarks_list = db.execute(query, params).fetchall()
    total_pages = (total + per_page - 1) // per_page
    
    return render_template(
        'bookmarks.html',
        bookmarks=bookmarks_list,
        search=search,
        filter_type=filter_type,
        page=page,
        total_pages=total_pages,
        total=total
    )


@app.route('/bookmark/add', methods=['POST'])
@login_required
def add_bookmark():
    """Add URL to bookmarks."""
    url = request.form.get('url', '').strip()
    result = request.form.get('result', '')
    confidence = request.form.get('confidence', 0)
    note = request.form.get('note', '')
    
    if url:
        db = get_db()
        db.execute('''
            INSERT INTO bookmarks (user_id, url, result, confidence, note)
            VALUES (?, ?, ?, ?, ?)
        ''', (session['user_id'], url, result, confidence, note))
        db.commit()
        flash('URL bookmarked successfully!', 'success')
    
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/bookmark/<int:bookmark_id>/delete', methods=['POST'])
@login_required
def delete_bookmark(bookmark_id):
    """Delete a bookmark."""
    db = get_db()
    db.execute('DELETE FROM bookmarks WHERE id = ? AND user_id = ?', 
               (bookmark_id, session['user_id']))
    db.commit()
    flash('Bookmark deleted.', 'success')
    return redirect(url_for('bookmarks'))


@app.route('/bookmark/<int:bookmark_id>/rescan')
@login_required
def rescan_bookmark(bookmark_id):
    """Rescan a bookmarked URL."""
    db = get_db()
    bookmark = db.execute('SELECT * FROM bookmarks WHERE id = ? AND user_id = ?',
                          (bookmark_id, session['user_id'])).fetchone()
    
    if bookmark:
        result = predict_url(bookmark['url'])
        save_scan(session['user_id'], bookmark['url'], result, 'rescan')
        flash(f'Rescan complete: {result["result"]} ({result["confidence"]}%)', 
              'success' if result['result'] == 'legitimate' else 'warning')
    
    return redirect(url_for('bookmarks'))


@app.route('/admin')
@admin_required
def admin():
    """Admin dashboard."""
    db = get_db()
    
    search = request.args.get('search', '')
    user_filter = request.args.get('filter', 'all')
    
    # Get statistics
    total_users = db.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    total_scans = db.execute('SELECT COUNT(*) as count FROM scans').fetchone()['count']
    total_phishing = db.execute(
        "SELECT COUNT(*) as count FROM scans WHERE result = 'phishing'"
    ).fetchone()['count']
    total_legitimate = db.execute(
        "SELECT COUNT(*) as count FROM scans WHERE result = 'legitimate'"
    ).fetchone()['count']
    
    # Get all users with scan counts - with search
    query = '''
        SELECT u.*, COUNT(s.id) as scan_count
        FROM users u
        LEFT JOIN scans s ON u.id = s.user_id
    '''
    params = []
    if search:
        query += ' WHERE u.username LIKE ? OR u.email LIKE ?'
        params = [f'%{search}%', f'%{search}%']
    
    query += ' GROUP BY u.id ORDER BY u.created_at DESC'
    
    users = db.execute(query, params).fetchall()
    
    # Get recent scans with user info
    recent_scans = db.execute('''
        SELECT s.*, u.username
        FROM scans s
        JOIN users u ON s.user_id = u.id
        ORDER BY s.created_at DESC
        LIMIT 50
    ''').fetchall()
    
    # Get scans per day for last 7 days
    scans_per_day = db.execute('''
        SELECT DATE(created_at) as date, COUNT(*) as count
        FROM scans
        WHERE created_at >= DATE('now', '-7 days')
        GROUP BY DATE(created_at)
        ORDER BY date DESC
    ''').fetchall()
    
    # Get scans per month for last 6 months
    scans_per_month = db.execute('''
        SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count
        FROM scans
        WHERE created_at >= DATE('now', '-6 months')
        GROUP BY strftime('%Y-%m', created_at)
        ORDER BY month DESC
    ''').fetchall()
    
    # Get top users by scan count
    top_users = db.execute('''
        SELECT u.id, u.username, COUNT(s.id) as scan_count
        FROM users u
        LEFT JOIN scans s ON u.id = s.user_id
        GROUP BY u.id
        ORDER BY scan_count DESC
        LIMIT 5
    ''').fetchall()
    
    # Get system health - new users today
    new_users_today = db.execute('''
        SELECT COUNT(*) as count FROM users 
        WHERE DATE(created_at) = DATE('now')
    ''').fetchone()['count']
    
    # Get scans today
    scans_today = db.execute('''
        SELECT COUNT(*) as count FROM scans 
        WHERE DATE(created_at) = DATE('now')
    ''').fetchone()['count']
    
    return render_template(
        'admin.html',
        total_users=total_users,
        total_scans=total_scans,
        total_phishing=total_phishing,
        total_legitimate=total_legitimate,
        users=users,
        recent_scans=recent_scans,
        scans_per_day=scans_per_day,
        scans_per_month=scans_per_month,
        top_users=top_users,
        new_users_today=new_users_today,
        scans_today=scans_today,
        search=search
    )


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Delete a user."""
    if user_id == session['user_id']:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin'))
    
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@admin_required
def admin_toggle_admin(user_id):
    """Toggle admin status for a user."""
    db = get_db()
    user = db.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if user:
        new_status = 0 if user['is_admin'] else 1
        db.execute('UPDATE users SET is_admin = ? WHERE id = ?', (new_status, user_id))
        db.commit()
        flash('User admin status updated.', 'success')
    
    return redirect(url_for('admin'))


@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    """View user details and scan history."""
    db = get_db()
    
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin'))
    
    total_scans = db.execute(
        'SELECT COUNT(*) as count FROM scans WHERE user_id = ?',
        (user_id,)
    ).fetchone()['count']
    
    phishing_count = db.execute(
        "SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND result = 'phishing'",
        (user_id,)
    ).fetchone()['count']
    
    safe_count = db.execute(
        "SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND result = 'legitimate'",
        (user_id,)
    ).fetchone()['count']
    
    stats = {
        'total_scans': total_scans,
        'phishing_count': phishing_count,
        'safe_count': safe_count
    }
    
    scans = db.execute('''
        SELECT * FROM scans 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 50
    ''', (user_id,)).fetchall()
    
    return render_template(
        'admin_user_detail.html',
        user=user,
        stats=stats,
        scans=scans
    )


@app.route('/api/docs')
def api_docs():
    """API documentation page."""
    return render_template('api_docs.html')


# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/api/check_url', methods=['POST'])
def api_check_url():
    """
    API endpoint to check a single URL.
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'Invalid URL format. URL must start with http:// or https://'}), 400
    
    result = predict_url(url)
    
    if 'error' in result:
        return jsonify({'error': result['error']}), 500
    
    return jsonify({
        'url': url,
        'result': result['result'],
        'confidence': result['confidence'],
        'is_phishing': result['is_phishing'],
        'is_legitimate': result['is_legitimate'],
        'features': result['features']
    })


@app.route('/api/batch_check', methods=['POST'])
def api_batch_check():
    """
    API endpoint to check multiple URLs.
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    urls = data.get('urls', [])
    
    if not urls or not isinstance(urls, list):
        return jsonify({'error': 'URLs array is required'}), 400
    
    if len(urls) > 100:
        return jsonify({'error': 'Maximum 100 URLs allowed per request'}), 400
    
    results = []
    
    for url in urls:
        if url.startswith(('http://', 'https://')):
            prediction = predict_url(url)
            results.append({
                'url': url,
                'result': prediction.get('result'),
                'confidence': prediction.get('confidence'),
                'is_phishing': prediction.get('is_phishing'),
                'is_legitimate': prediction.get('is_legitimate'),
                'error': prediction.get('error')
            })
        else:
            results.append({
                'url': url,
                'error': 'Invalid URL format'
            })
    
    return jsonify({
        'total': len(urls),
        'results': results
    })


@app.route('/api/stats')
def api_stats():
    """
    API endpoint to get system statistics.
    """
    db = get_db()
    
    stats = {
        'total_users': db.execute('SELECT COUNT(*) as count FROM users').fetchone()['count'],
        'total_scans': db.execute('SELECT COUNT(*) as count FROM scans').fetchone()['count'],
        'phishing_detected': db.execute(
            "SELECT COUNT(*) as count FROM scans WHERE result = 'phishing'"
        ).fetchone()['count'],
        'legitimate_detected': db.execute(
            "SELECT COUNT(*) as count FROM scans WHERE result = 'legitimate'"
        ).fetchone()['count']
    }
    
    return jsonify(stats)


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors."""
    if request.is_json:
        return jsonify({'error': 'Not found'}), 404
    flash('Page not found.', 'warning')
    return redirect(url_for('index'))


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    if request.is_json:
        return jsonify({'error': 'Internal server error'}), 500
    flash('An internal error occurred. Please try again.', 'danger')
    return redirect(url_for('index'))


@app.errorhandler(413)
def too_large(error):
    """Handle file too large error."""
    flash('File too large. Maximum size is 16MB.', 'danger')
    return redirect(request.url)


# ============================================================================
# CONTEXT PROCESSORS
# ============================================================================

@app.context_processor
def inject_globals():
    """Inject global variables into templates."""
    return {
        'now': datetime.now(),
        'datetime': datetime,
        'app_name': 'ShieldGuard Pro',
        'version': '1.0.0'
    }


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    # Ensure database is initialized
    with app.app_context():
        init_db()
    
    # Run the application
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )

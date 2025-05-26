import os
import random
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import pyotp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import uuid

app = Flask(__name__)

# Setup database path
basedir = os.path.abspath(os.path.dirname(__file__))
db_folder = os.path.join(basedir, 'instance')
db_path = os.path.join(db_folder, 'ees.db')
if not os.path.exists(db_folder):
    os.makedirs(db_folder)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SMTP config from env vars or set here for testing
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '765muhammadmeesam765@gmail.com')  # Change for testing
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', 'xtnf mhhc mcko meip')    # Change for testing
FROM_EMAIL = SMTP_USERNAME

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    rsa_public_key = db.Column(db.Text, nullable=True)
    rsa_private_key = db.Column(db.Text, nullable=True)
    totp_secret = db.Column(db.String(16), nullable=True)  # 2FA secret
    # Track login attempts
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_rsa_keys(self):
        key = RSA.generate(2048)
        self.rsa_private_key = key.export_key().decode()
        self.rsa_public_key = key.publickey().export_key().decode()

    def get_totp_uri(self):
        return f'otpauth://totp/EncryptedEmail:{self.email}?secret={self.totp_secret}&issuer=EncryptedEmail'

    def verify_totp(self, token):
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)


class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_email = db.Column(db.String(100), nullable=True)
    encrypted_message = db.Column(db.Text, nullable=False)
    encrypted_aes_key = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='sent')  # 'inbox', 'sent', 'draft'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', backref='sent_emails')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def send_email(to_email, subject, html_body):
    try:
        msg = MIMEMultipart()
        msg['From'] = FROM_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(html_body, 'html'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(FROM_EMAIL, to_email, msg.as_string())
        server.quit()
        print("Email sent successfully.")
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False


def check_password_strength(password):
    if (len(password) < 8 or
        not re.search(r'[A-Z]', password) or
        not re.search(r'[a-z]', password) or
        not re.search(r'\d', password) or
        not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
        return False
    return True


def encrypt_email(message, receiver_public_key_pem):
    aes_key = get_random_bytes(32)  # AES-256
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

    encrypted_message = base64.b64encode(cipher_aes.nonce + tag + ciphertext).decode()

    receiver_public_key = RSA.import_key(receiver_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(receiver_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode()

    return encrypted_message, encrypted_aes_key_b64


def decrypt_email(encrypted_message_b64, encrypted_aes_key_b64, receiver_private_key_pem):
    encrypted_message = base64.b64decode(encrypted_message_b64)
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)

    receiver_private_key = RSA.import_key(receiver_private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(receiver_private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    nonce = encrypted_message[:16]
    tag = encrypted_message[16:32]
    ciphertext = encrypted_message[32:]
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_message.decode()


def is_login_allowed(user):
    if user.failed_login_attempts >= 3:
        if user.last_failed_login and datetime.utcnow() < user.last_failed_login + timedelta(seconds=30):
            return False, int((user.last_failed_login + timedelta(seconds=30) - datetime.utcnow()).total_seconds())
        else:
            user.failed_login_attempts = 0
            user.last_failed_login = None
            db.session.commit()
    return True, 0


@app.before_request
def enforce_2fa():
    allowed_routes = ['login', 'send_2fa_code', 'verify_2fa', 'logout', 'static']
    if current_user.is_authenticated and not session.get('2fa_passed'):
        if request.endpoint not in allowed_routes:
            return redirect(url_for('send_2fa_code'))
            
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)



@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('inbox'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        if not check_password_strength(password):
            flash('Password must be at least 8 characters long and contain uppercase, lowercase, digit, and special character.', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        user.generate_rsa_keys()
        user.totp_secret = pyotp.random_base32()
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if session.get('2fa_passed'):
            return redirect(url_for('inbox'))
        else:
            return redirect(url_for('send_2fa_code'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            allowed, cooldown = is_login_allowed(user)
            if not allowed:
                flash(f'Too many failed attempts. Please wait {cooldown} seconds before trying again.', 'danger')
                return render_template('login.html')
            if user.check_password(password):
                # Reset failed attempts on successful login
                user.failed_login_attempts = 0
                user.last_failed_login = None
                db.session.commit()

                # Do NOT log in the user yet, redirect to 2FA
                session['pre_2fa_userid'] = user.id
                session['2fa_passed'] = False
                session['2fa_code'] = None
                session['2fa_expiry'] = None
                return redirect(url_for('send_2fa_code'))
            else:
                # Increment failed attempts
                user.failed_login_attempts += 1
                user.last_failed_login = datetime.utcnow()
                db.session.commit()
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')
@app.route('/send_2fa_code')
def send_2fa_code():
    if 'pre_2fa_userid' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['pre_2fa_userid'])
    if not user:
        flash("User not found. Please login again.", "danger")
        return redirect(url_for('login'))

    # Generate 6-digit code
    code = str(random.randint(100000, 999999))
    session['2fa_code'] = code
    session['2fa_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()

    email_body = f"""
    <p>Your two-factor authentication code is: <strong>{code}</strong>.</p>
    <p>This code will expire in 5 minutes.</p>
    """

    if send_email(user.email, "Your 2FA Code", email_body):
        flash('A 6-digit authentication code has been sent to your email.', 'info')
    else:
        flash('Failed to send 2FA email. Please try again later.', 'danger')

    return redirect(url_for('verify_2fa'))


@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_2fa_userid' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['pre_2fa_userid'])
    if not user:
        flash("User not found. Please login again.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        input_code = request.form.get('code')
        stored_code = session.get('2fa_code')
        expiry = session.get('2fa_expiry')

        if not stored_code or not expiry:
            flash('2FA code expired or missing. Please request a new one.', 'danger')
            return redirect(url_for('send_2fa_code'))

        if datetime.utcnow() > datetime.fromisoformat(expiry):
            flash('2FA code expired. Please request a new one.', 'danger')
            return redirect(url_for('send_2fa_code'))

        if input_code == stored_code:
            # Now login the user for real
            login_user(user)
            session.pop('pre_2fa_userid', None)
            session['2fa_passed'] = True
            flash('2FA verification successful!', 'success')
            return redirect(url_for('inbox'))
        else:
            flash('Invalid 2FA code. Try again.', 'danger')

    return render_template('verify_2fa.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('2fa_passed', None)
    session.pop('2fa_code', None)
    session.pop('2fa_expiry', None)
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))


@app.route('/reauth', methods=['GET', 'POST'])
@login_required
def reauth():
    if request.method == 'POST':
        password = request.form['password']
        if current_user.check_password(password):
            session['reauthenticated'] = True
            return redirect(url_for('inbox'))
        else:
            flash('Incorrect password.', 'danger')
            return redirect(url_for('reauth'))
    return render_template('reauth.html')


@app.route('/inbox')
@login_required
def inbox():
    if not session.get('reauthenticated'):
        return redirect(url_for('reauth'))
    emails = Email.query.filter_by(receiver_email=current_user.email, status='inbox').order_by(Email.timestamp.desc()).all()
    return render_template('inbox.html', emails=emails)


@app.route('/sent')
@login_required
def sent():
    emails = Email.query.filter_by(sender_id=current_user.id, status='sent').order_by(Email.timestamp.desc()).all()
    return render_template('sent.html', emails=emails)


@app.route('/drafts')
@login_required
def drafts():
    drafts = Email.query.filter_by(sender_id=current_user.id, status='draft').order_by(Email.timestamp.desc()).all()
    return render_template('drafts.html', drafts=drafts)


@app.route('/compose', methods=['GET', 'POST'])
@login_required
def compose():
    if request.method == 'POST':
        receiver = request.form.get('receiver')
        message = request.form.get('message')
        save_as_draft = request.form.get('save_as_draft')

        if not message or (not receiver and not save_as_draft):
            flash('Receiver and message are required unless saving as draft.', 'danger')
            return redirect(url_for('compose'))

        if save_as_draft:
            encrypted_msg = ''
            encrypted_key = ''
            if message:
                encrypted_msg, encrypted_key = encrypt_email(message, current_user.rsa_public_key)
            draft = Email(
                sender_id=current_user.id,
                receiver_email=receiver if receiver else '',
                encrypted_message=encrypted_msg,
                encrypted_aes_key=encrypted_key,
                status='draft'
            )
            db.session.add(draft)
            db.session.commit()
            flash('Draft saved!', 'info')
            return redirect(url_for('drafts'))

        receiver_user = User.query.filter_by(email=receiver).first()
        if not receiver_user:
            flash('Receiver email not found in system.', 'danger')
            return redirect(url_for('compose'))

        encrypted_msg, encrypted_key = encrypt_email(message, receiver_user.rsa_public_key)

        sent_email = Email(
            sender_id=current_user.id,
            receiver_email=receiver,
            encrypted_message=encrypted_msg,
            encrypted_aes_key=encrypted_key,
            status='sent'
        )
        inbox_email = Email(
            sender_id=current_user.id,
            receiver_email=receiver,
            encrypted_message=encrypted_msg,
            encrypted_aes_key=encrypted_key,
            status='inbox'
        )
        db.session.add_all([sent_email, inbox_email])
        db.session.commit()
        flash('Encrypted email sent!', 'success')
        return redirect(url_for('sent'))

    return render_template('compose_email.html')


@app.route('/email/<int:email_id>')
@login_required
def view_email(email_id):
    email = Email.query.get_or_404(email_id)
    if email.receiver_email != current_user.email and email.sender_id != current_user.id:
        abort(403)

    decrypted_message = None
    if email.status != 'draft' and email.receiver_email == current_user.email:
        try:
            decrypted_message = decrypt_email(
                email.encrypted_message,
                email.encrypted_aes_key,
                current_user.rsa_private_key
            )
        except Exception:
            decrypted_message = "[Decryption failed]"

    return render_template('view_email.html', email=email, decrypted_message=decrypted_message)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = str(uuid.uuid4())
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()

            reset_link = url_for('reset_password', token=token, _external=True)
            email_body = f'''
                <p>Hello {user.username},</p>
                <p>Click the link below to reset your password (valid for 1 hour):</p>
                <p><a href="{reset_link}">{reset_link}</a></p>
                <p>If you did not request this, please ignore this email.</p>
            '''
            try:
                send_email(user.email, "Password Reset Request", email_body)
                flash('Password reset email sent! Check your inbox.', 'info')
            except Exception as e:
                flash(f'Failed to send email: {e}', 'danger')
        else:
            flash('Email not found.', 'danger')
        return redirect(url_for('login'))

    return render_template('reset_password_request.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or user.reset_token_expiry < datetime.utcnow():
        flash('Invalid or expired reset token.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        if not check_password_strength(password):
            flash('Password must be at least 8 characters long and contain uppercase, lowercase, digit, and special character.', 'danger')
            return redirect(url_for('reset_password', token=token))
        user.set_password(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        flash('Password reset successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

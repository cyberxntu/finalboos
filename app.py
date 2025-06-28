from flask import Flask, request, redirect, render_template, session, flash
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField
from wtforms.validators import DataRequired, Length
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
csrf = CSRFProtect(app)

DATABASE = 'db.sqlite'

# ======== DB SETUP ========
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
            balance INTEGER DEFAULT 1000,
            role TEXT DEFAULT 'user'
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

# ======== FORMS ========
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class TransferForm(FlaskForm):
    to = StringField('To', validators=[DataRequired()])
    amount = IntegerField('Amount', validators=[DataRequired()])

class CommentForm(FlaskForm):
    comment = StringField('Comment', validators=[DataRequired()])


# ======== ROUTES ========
@app.route('/')
def index():
    conn = get_db()
    comments = conn.execute("SELECT * FROM comments").fetchall()
    return render_template('index.html', comments=comments)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        hashed_pw = generate_password_hash(password)
        try:
            conn = get_db()
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            flash("Registration successful. Please login.")
            return redirect('/login')
        except:
            flash("Username already exists.")
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['user_id'] = user['id']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect('/admin')
            return redirect('/dashboard')
        else:
            flash("Invalid username or password.")
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db()
    user = conn.execute("SELECT balance FROM users WHERE id=?", (session['user_id'],)).fetchone()
    form = TransferForm()

    if form.validate_on_submit():
        to_user = form.to.data
        amount = form.amount.data

        if amount <= 0:
            flash("Invalid amount.")
            return redirect('/dashboard')

        current_balance = user['balance']
        if current_balance < amount:
            flash("Insufficient balance.")
            return redirect('/dashboard')

        recipient = conn.execute("SELECT id FROM users WHERE username=?", (to_user,)).fetchone()
        if not recipient:
            flash("Recipient not found.")
            return redirect('/dashboard')

        conn.execute("UPDATE users SET balance = balance - ? WHERE id=?", (amount, session['user_id']))
        conn.execute("UPDATE users SET balance = balance + ? WHERE username=?", (amount, to_user))
        conn.commit()
        flash("Transfer successful.")

    return render_template('dashboard.html', username=session['username'], balance=user['balance'], form=form)

@app.route('/comment', methods=['POST'])
def comment():
    if 'username' not in session:
        return redirect('/login')
    form = CommentForm()
    if form.validate_on_submit():
        content = form.comment.data
        conn = get_db()
        conn.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (session['username'], content))
        conn.commit()
    return redirect('/')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if session.get('role') != 'admin' or 'username' not in session:
        return redirect('/login')

    form = CommentForm()
    if form.validate_on_submit():
        flash(f"Post received: {form.comment.data}")
    return render_template('admin.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=False)

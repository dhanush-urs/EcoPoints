# Updated Flask app with responsive templates

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from jinja2 import DictLoader
from datetime import date

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///waste.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# -------------------------------
# MODELS
# -------------------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    points = db.Column(db.Integer, default=0)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default="Pending")
    date = db.Column(db.String(20), default=lambda: str(date.today()))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------------
# HTML TEMPLATES (MOBILE RESPONSIVE)
# -------------------------------

templates = {
    "base.html": """
<!DOCTYPE html>
<html>
<head>
    <title>EcoPoints</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

    <style>
        .mobile-padding { padding: 10px; }
        @media (max-width: 768px) {
            .navbar .btn { padding: 4px 8px; font-size: 14px; margin: 3px; }
            table { font-size: 14px; }
        }
    </style>
</head>
<body class="bg-light">

<nav class="navbar navbar-expand-lg navbar-dark bg-success">
  <div class="container-fluid">
    <a class="navbar-brand" href="/">EcoPoints</a>
    <div>
      {% if current_user.is_authenticated %}
        <a class="btn btn-light me-2" href="/dashboard">Dashboard</a>
        <a class="btn btn-light me-2" href="/shop">Shop</a>
        {% if current_user.is_admin %}
          <a class="btn btn-warning me-2" href="/admin">Admin</a>
        {% endif %}
        <a class="btn btn-danger" href="/logout">Logout</a>
      {% else %}
        <a class="btn btn-light" href="/login">Login</a>
        <a class="btn btn-light" href="/register">Register</a>
      {% endif %}
    </div>
  </div>
</nav>

<div class="container mt-4">
  {% with messages = get_flashed_messages() %}
    {% for msg in messages %}
      <div class="alert alert-info">{{ msg }}</div>
    {% endfor %}
  {% endwith %}
  {% block content %}{% endblock %}
</div>

</body>
</html>
""",

    "index.html": """
{% extends 'base.html' %}
{% block content %}
<div class="text-center mt-5 mobile-padding">
  <h1 class="text-success fw-bold">EcoPoints</h1>
  <p class="lead">Earn eco-points daily for waste segregation!</p>
  <a href="/register" class="btn btn-success btn-lg w-100 mt-3">Get Started</a>
</div>
{% endblock %}
""",

    "register.html": """
{% extends 'base.html' %}
{% block content %}
<h2 class="mb-3">Register</h2>
<form method="POST" class="mobile-padding">
  <input type="text" class="form-control mb-3" name="username" placeholder="Username" required>
  <input type="password" class="form-control mb-3" name="password" placeholder="Password" required>
  <button type="submit" class="btn btn-success w-100">Register</button>
</form>
{% endblock %}
""",

    "login.html": """
{% extends 'base.html' %}
{% block content %}
<h2 class="mb-3">Login</h2>
<form method="POST" class="mobile-padding">
  <input type="text" class="form-control mb-3" name="username" placeholder="Username" required>
  <input type="password" class="form-control mb-3" name="password" placeholder="Password" required>
  <button type="submit" class="btn btn-success w-100">Login</button>
</form>
{% endblock %}
""",

    "dashboard.html": """
{% extends 'base.html' %}
{% block content %}
<h2>Hello, {{ current_user.username }}!</h2>
<p>Your points: <b>{{ current_user.points }}</b></p>

<h4>Your Daily Submissions:</h4>

<div class="table-responsive">
  <table class="table table-striped">
    <tr><th>Date</th><th>Status</th></tr>
    {% for s in submissions %}
      <tr>
        <td>{{ s.date }}</td>
        <td>{{ s.status }}</td>
      </tr>
    {% endfor %}
  </table>
</div>

{% endblock %}
""",

    "admin.html": """
{% extends 'base.html' %}
{% block content %}
<h2>Admin Panel — Today's Requests</h2>

<div class="table-responsive">
<table class="table table-bordered">
  <tr><th>User</th><th>Date</th><th>Status</th><th>Action</th></tr>
  {% for s in submissions %}
  <tr>
    <td>{{ users[s.user_id] }}</td>
    <td>{{ s.date }}</td>
    <td>{{ s.status }}</td>
    <td>
      {% if s.status == 'Pending' %}
        <a href="/approve/{{ s.id }}" class="btn btn-success btn-sm w-100 mb-1">Yes</a>
        <a href="/reject/{{ s.id }}" class="btn btn-danger btn-sm w-100">No</a>
      {% else %}
        {{ s.status }}
      {% endif %}
    </td>
  </tr>
  {% endfor %}
</table>
</div>

{% if submissions|length == 0 %}
<p class="text-muted">No pending submissions for today 🎉</p>
{% endif %}

{% endblock %}
""",

    "shop.html": """
{% extends 'base.html' %}
{% block content %}
<h2>Eco Shop 🛍️</h2>
<p>Your Points: <b>{{ current_user.points }}</b></p>

<div class="row row-cols-1 row-cols-md-2 g-3 mt-3">
  {% for item in items %}
  <div class="col">
    <div class="card shadow-sm">
      <div class="card-body">
        <h5 class="card-title">{{ item.name }}</h5>
        <p class="card-text">{{ item.desc }}</p>
        <p><b>Cost:</b> {{ item.cost }} points</p>
        <a href="/buy/{{ item.key }}" class="btn btn-success w-100">Buy</a>
      </div>
    </div>
  </div>
  {% endfor %}
</div>

{% endblock %}
"""
}

app.jinja_loader = DictLoader(templates)

# -------------------------------
# ROUTES
# -------------------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(username=username).first():
            flash("Username already exists!")
        else:
            user = User(username=username, password=password)
            db.session.add(user)
            db.session.commit()
            flash("Registered successfully!")
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))

        flash("Invalid credentials!")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    subs = Submission.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', submissions=subs)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash("Access denied!")
        return redirect(url_for('dashboard'))

    today = str(date.today())
    subs = Submission.query.filter_by(date=today).all()
    users = {u.id: u.username for u in User.query.all()}

    return render_template('admin.html', submissions=subs, users=users)

@app.route('/approve/<int:id>')
@login_required
def approve(id):
    if not current_user.is_admin:
        flash("Not allowed")
        return redirect(url_for('dashboard'))

    sub = Submission.query.get(id)
    sub.status = "Approved"

    usr = User.query.get(sub.user_id)
    usr.points += 10

    db.session.commit()
    flash("Submission approved!")

    return redirect(url_for('admin'))

@app.route('/reject/<int:id>')
@login_required
def reject(id):
    if not current_user.is_admin:
        flash("Not allowed")
        return redirect(url_for('dashboard'))

    sub = Submission.query.get(id)
    sub.status = "Rejected"

    db.session.commit()
    flash("Submission rejected!")

    return redirect(url_for('admin'))

@app.route('/shop')
@login_required
def shop():
    items = [
        {"key": "bottle","name": "Eco Bottle","desc": "Steel Bottle","cost":20},
        {"key": "bag","name": "Recycled Bag","desc": "Eco-friendly Bag","cost":30},
        {"key": "notebook","name": "Eco Notebook","desc": "Recycled Paper","cost":25},
        {"key": "plant","name": "Mini Plant","desc": "Desk Plant","cost":40},
    ]

    return render_template('shop.html', items=items)

@app.route('/buy/<item>')
@login_required
def buy(item):
    shop = {
        "bottle":{"cost":20,"name":"Eco Bottle"},
        "bag":{"cost":30,"name":"Recycled Bag"},
        "notebook":{"cost":25,"name":"Eco Notebook"},
        "plant":{"cost":40,"name":"Mini Plant"}
    }

    if item not in shop:
        flash("Invalid item!")
        return redirect(url_for('shop'))

    cost = shop[item]["cost"]
    name = shop[item]["name"]

    if current_user.points >= cost:
        current_user.points -= cost
        db.session.commit()
        flash(f"Purchased {name}!")
    else:
        flash("Not enough points!")

    return redirect(url_for('shop'))

# ---------------------------------------------
# AUTO CREATE DAILY SUBMISSION
# ---------------------------------------------

@app.before_request
def daily_entry():
    db.create_all()

    today = str(date.today())
    users = User.query.all()

    for u in users:
        if not u.is_admin:
            exists = Submission.query.filter_by(user_id=u.id, date=today).first()
            if not exists:
                db.session.add(Submission(user_id=u.id, date=today))

    db.session.commit()

# -------------------------------
# RUN SERVER
# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            return redirect(url_for('secret'))
        else:
            flash('Invalid email or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']


        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('signup'))

        if not re.search(r'[A-Z]', password):
            flash('Password must have an upper case letter somewhere.')
            return redirect(url_for('signup'))
        
        if not re.search(r'[a-z]', password):
            flash('Password must have a lower case letter somewhere.')
            return redirect(url_for('signup'))
        
        if not re.search(r'[0-9]$', password):
            flash('Password must have a number at the end.')
            return redirect(url_for('signup'))

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('thankyou'))
    return render_template('signup.html')

@app.route('/secret')
def secret():
    return render_template('secretPage.html')

@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

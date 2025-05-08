from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, login_required, logout_user
from sqlalchemy import text
from .models import User
from . import db, app

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()
    
 #  verify hash, never include raw password in your SQL
    if not user or not check_password_hash(user.password, password):
        flash("Invalid email or password.", category='error')
        return redirect(url_for('auth.login'))


    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash("An account with that email already exists.", category='error')
        return redirect(url_for('auth.signup'))


     # hash the password before storing
    hashed_pw = generate_password_hash(password, method='sha256')
    new_user = User(email=email, name=name, password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()


    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user();
    return redirect(url_for('main.index'))

# See https://www.digitalocean.com/community/tutorials/how-to-add-authentication-to-your-app-with-flask-login for more information

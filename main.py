from flask import Flask, render_template, redirect, url_for, flash, abort, session, request
from flask_bootstrap import Bootstrap5
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
# the current_user acts as a object for the particular user of the user table who has logged in .
# with the current_user we can able to access the attributes of the user table of the current user who is logged in.
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, Float
from functools import wraps
import random
import time
import smtplib
import os
# used to remove the %20 in the parameters from the route.
from urllib.parse import unquote

# enables a admin interface like django to add the contents in the database
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

from werkzeug.security import generate_password_hash, check_password_hash


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        # Check if the user is authenticated
        if not current_user.is_authenticated:
            return abort(403)  # Return Forbidden if the user is not authenticated
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return function(*args, **kwargs)
    return decorated_function


app = Flask(__name__)
app.config['SECRET_KEY'] = "lsdfeownofflrwerowjsdskfjsowiohsorjoitew"
Bootstrap5(app)


# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# every time it is called when request is made
# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(Users, user_id)
    # it checks the user id in the session and that userid is present in the database.
# For every subsequent request, Flask-Login calls the user_loader function to load the user object associated with the user_id stored in the session.
# The load_user function retrieves the User from the database based on the stored user_id. This allows you to access the current user in the request using current_user.


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


# configuring and initilizing the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tables.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# TODO: Create a User table for all your registered users.
# CONFIGURE TABLES
class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))


class AdminUser(UserMixin, db.Model):
    __tablename__ = "admin"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))


class Specialist(UserMixin, db.Model):
    __tablename__ = "specialist"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))


# creating the tables in the database
with app.app_context():
    db.create_all()


# admin panel initialization
admin = Admin(app, name='Agro Care', template_mode='bootstrap3')  # admin obj for admin panel with name Agro Care
# allows only the admin to access the /admin route


class AdminModelView(ModelView):
    @admin_only
    def is_accessible(self):
        return current_user.is_authenticated and current_user.id == 1
    # this function returns true if the current_user is authenticated and current_user id is 1 else it returns false
    # if it is true then it shows the admin panel with the database eg: MyRestaurant Home Items.
    # if it is false then it shows the admin panel without the database. MyRestaurant Home.


# This creates a new administrative interface for the User model. The first parameter, User, is the model you want to manage. The second parameter, db.session, is the SQLAlchemy session used for database transactions.
# ModelView creates an interface in the /admin panel to manage (view, add, edit, delete) your database models.
admin.add_view(AdminModelView(Users, db.session))  # this calls the functions inside the class AdminModelView


@app.route("/")
def landingpage():
    return render_template("landingpage.html")


@app.route("/home")
def home():
    # only allows the user when he is logged in.
    if not current_user.is_authenticated:
        flash("First Log in and try again!")
        return redirect(url_for("landingpage"))

    user = request.args.get("user")
    # if the user is an admin then this route will be executed and it passes that it is admin. (user=user)
    if user == "admin":
        return render_template("index.html", user=user, logged_in=current_user.is_authenticated)
    # else the user is a specialist or a normal user. so the user contains either true or false
    # if it is false then it is a user . if it is true then it is specialist. these things can be done in base.html.
    else:
        return render_template("index.html", specialist=user, logged_in=current_user.is_authenticated)


@app.route("/register", methods=['POST'])
def register():

    if request.method == "POST":
        # to clarify the logged in user is a specialist or a normal user. by default setting as false
        # if it remains false then the logged in user is a normal user else he is a specialist
        specialist = "no"

        # checking that the email is already exists. if it is then we need to send the flash message and redirect page to login
        email = request.form.get("email")
        name = request.form.get("name")
        password = request.form.get("password")

        # this is the one that tells in which form it has came from. there are two forms for register, specialist and user
        form_name = request.args.get("form_name")

        # Find user and specialist by email entered.
        if form_name and form_name == "user":
            email_in_database = db.session.execute(db.select(Users).where(Users.email == email)).scalar()
        else:  # check for specialist
            email_in_database = db.session.execute(db.select(Specialist).where(Specialist.email == email)).scalar()
            specialist = "yes"

        # check if email exists
        if email_in_database:
            # user already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('landingpage'))  # flash message is sent along with this router.

        # hashing and salting the password entered by the user
        hashed_password = generate_password_hash(password=password,
                                                 method="pbkdf2:sha256",
                                                 salt_length=8)

        # entering the new user to the database
        if specialist == "no":
            new_user = Users(
                email=email,
                password=hashed_password,
                name=name
            )
            db.session.add(new_user)
            db.session.commit()
            # Log in and authenticate user after adding details to database.
            login_user(new_user)  # Logs in a user by saving their ID in the session.

        else:
            new_user = Specialist(
                email=email,
                password=hashed_password,
                name=name
            )
            db.session.add(new_user)
            db.session.commit()

            # Log in and authenticate user after adding details to database.
            login_user(new_user)  # Logs in a user by saving their ID in the session.

        return redirect(url_for("home", user=specialist))


@app.route("/login", methods=['POST'])
def login():

    if request.method == "POST":
        # to clarify the logged in user is a specialist or a normal user. by default setting as false
        # if it remains false then the logged in user is a normal user else he is a specialist
        specialist = "no"
        adminuser = None

        email = request.form.get("email")
        password = request.form.get("password")
        # this is the one that tells in which form it has came from. there are two forms for login, admin and users
        form_name = request.args.get("form_name")

        # finds the user and admin by email entered
        if form_name and form_name == "admin":
            # checking that the user is exist, who tries to login
            user = db.session.execute(db.select(AdminUser).where(AdminUser.email == email)).scalar()
            adminuser = "admin"
        else:
            # checking that the logging user is a specialist or a normal user
            user = db.session.execute(db.select(Users).where(Users.email == email)).scalar()
            if not user:
                user = db.session.execute(db.select(Specialist).where(Specialist.email == email)).scalar()
                specialist = "yes"


        # if the user is not present then send a flash message with that route
        if not user:
            flash("That mail does not exist. please try again!")
            return redirect(url_for("landingpage"))

            # Check stored password hash against entered password hashed. if it is not same then send a flash message
        elif not check_password_hash(user.password, password):
            flash("Password incorrect please try again!")
            return redirect(url_for("landingpage"))

            # if the email and password are entered correctly
        else:
            login_user(user)  # Logs in a user by saving their ID in the session.
            if adminuser == "admin":  # if it is admin then pass admin else pass specialist or user.
                return redirect(url_for('home', user=adminuser))
            else:
                return redirect(url_for('home', user=specialist))


@app.route('/logout')
def logout():
    logout_user()  # logout the user by removing the user id from the session
    return redirect(url_for('landingpage'))


if __name__ == "__main__":
    app.run(debug=True)
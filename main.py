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
        # if the current user is not from the AdminUser table
        if not isinstance(current_user, AdminUser):
            return abort(403)
        # Otherwise continue with the route function
        return function(*args, **kwargs)
    return decorated_function


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("Soil_Crop_Flask_Secretkey")
Bootstrap5(app)


# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# every time it is called when request is made
# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    composite_id = session.get("user_id")
    print(f"Loading user with ID: {composite_id}")

    if composite_id.startswith("user_"):

        user_id = int(composite_id.split("_")[1])  # Extract the numeric ID
        user = db.get_or_404(Users, user_id)
        if user:
            print(f"Found user in Users table: {user}")
            return user

    elif composite_id.startswith("specialist_"):
        user_id = int(composite_id.split("_")[1])  # Extract the numeric ID
        user = db.get_or_404(Specialist, user_id)
        if user:
            print(f"Found user in Specialist table: {user}")
            return user

    elif composite_id.startswith("admin_"):
        print("no")
        user_id = int(composite_id.split("_")[1])  # Extract the numeric ID
        user = db.get_or_404(AdminUser, user_id)
        if user:
            print(f"Found user in AdminUser table: {user}")
            return user

    print("User not found in any table")
    return None
    # it checks the user id in the session and that userid is present in the database.
# For every subsequent request, Flask-Login calls the user_loader function to load the user object associated with the user_id stored in the session.
# The load_user function retrieves the User from the database based on the stored user_id. This allows you to access the current user in the request using current_user.


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


# configuring and initilizing the database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("Soil_Crop_Database_SecretKey")
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
    specialization: Mapped[str] = mapped_column(String(100))


class Soil(db.Model):
    __tablename__ = "soil"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    texture: Mapped[str] = mapped_column(String(50), nullable=False)
    nutrients: Mapped[str] = mapped_column(String(255), nullable=False)
    best_suited_crops: Mapped[str] = mapped_column(String(255), nullable=False)
    image: Mapped[str] = mapped_column(String(255), nullable=True)  # Image path


class Crop(db.Model):
    __tablename__ = "crop"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    soil_type: Mapped[str] = mapped_column(String(255), nullable=False)
    growing_season: Mapped[str] = mapped_column(String(100), nullable=False)
    water_requirement: Mapped[str] = mapped_column(String(50), nullable=False)
    image: Mapped[str] = mapped_column(String(255), nullable=True)  # Image path


# if the specialist fill the form of the crop details, then it is stored here. and visible to admin
class DistributorCropDetails(db.Model):
    __tablename__ = "distributor_crop_details"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    distributor_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    crop_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    location: Mapped[str] = mapped_column(String(50), nullable=False)
    soil_type: Mapped[str] = mapped_column(String(255), nullable=False)
    growing_season: Mapped[str] = mapped_column(String(100), nullable=False)
    address: Mapped[str] = mapped_column(String(100), nullable=False)
    image: Mapped[str] = mapped_column(String(255), nullable=True)  # Image path
    contact_number: Mapped[str] = mapped_column(Integer, nullable=True)


# if the specialist fill the form of the soil details, then it is stored here. and visible to admin
class DistributorSoilDetails(db.Model):
    __tablename__ = "distributor_soil_details"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    distributor_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    soil_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    location: Mapped[str] = mapped_column(String(50), nullable=False)
    address: Mapped[str] = mapped_column(String(250), nullable=False)
    nutrients: Mapped[str] = mapped_column(String(255), nullable=False)
    best_suited_crops: Mapped[str] = mapped_column(String(255), nullable=False)
    image: Mapped[str] = mapped_column(String(255), nullable=True)  # Image path
    contact_number: Mapped[str] = mapped_column(Integer, nullable=True)


class Details(db.Model):
    __tablename__ = "details"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    distributor_name: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(50), nullable=False)
    location: Mapped[str] = mapped_column(String(50), nullable=False)
    address: Mapped[str] = mapped_column(String(250), nullable=False)
    number: Mapped[int] = mapped_column(Integer, nullable=False)



# creating the tables in the database
with app.app_context():
    db.create_all()


# admin panel initialization
admin = Admin(app, name='Agro Care', template_mode='bootstrap3')  # admin obj for admin panel with name Agro Care
# allows only the admin to access the /admin route


class AdminModelView(ModelView):
    @admin_only
    def is_accessible(self):

        return current_user.is_authenticated and current_user.id == 1 and isinstance(current_user, AdminUser)
    # this function returns true if the current_user is authenticated and current_user id is 1 and isinstance is true. else it returns false
    # if it is true then it shows the admin panel with the database eg: Agro Care Home users.
    # if it is false then it shows the admin panel without the database. Agro Care Home.


# This creates a new administrative interface for the User model. The first parameter, User, is the model you want to manage. The second parameter, db.session, is the SQLAlchemy session used for database transactions.
# ModelView creates an interface in the /admin panel to manage (view, add, edit, delete) your database models.
admin.add_view(AdminModelView(Soil, db.session))  # this calls the functions inside the class AdminModelView
admin.add_view(AdminModelView(Crop, db.session))
admin.add_view(AdminModelView(DistributorSoilDetails, db.session))
admin.add_view(AdminModelView(DistributorCropDetails, db.session))
admin.add_view(AdminModelView(Details, db.session))


@app.route("/")
def landingpage():
    # if the user is not authenticated then show the login and register page
    if not current_user.is_authenticated:
        return render_template("landingpage.html")

    # if the user is authenticated then the login and register page should not be shown.
    # and home function route gets role as a path parameter.(optional) we can also make it as query parameter.
    # so we have to pass it. if we didnt pass then the role will be None. role is used in base.html
    # index.html page will be rendered by the home function. if the user is authenticated then we have current_user. so check current_user with isinstance
    else:
        role = None
        # role is used to show contact_admin for specialist in the index.html. and show the admin name if the role is admin
        # so it is not used for any thing except this one.
        if isinstance(current_user, Specialist):
            role = "specialist"
        if isinstance(current_user, AdminUser):
            role = "admin"

        # why i didnt give for user, because though he is a logged in user he might be an user.
        return redirect(url_for("home", role=role))


@app.route("/home")
def home():

    # only allows the user when he is logged in.don't allow if he is not authenticated
    if not current_user.is_authenticated:
        flash("First Log in and try again!")
        return redirect(url_for("landingpage"))

    role = request.args.get("role")
    print(role)
    # need to send the database details to the index.html for soil and crops details.
    soils = db.session.execute(db.select(Soil).order_by(Soil.name)).scalars().all()
    crops = db.session.execute(db.select(Crop).order_by(Crop.name)).scalars().all()

    return render_template("index.html", role=role, soils=soils, crops=crops, logged_in=current_user.is_authenticated)
    # things happening in base.html
    # if the user == "admin" then we need to display the admin name
    # if the  user == "specialist" then we need to display the admin name and also contact admin
    # if both are false then the logged in user is a normal user.


@app.route("/register", methods=['POST'])
def register():

    if request.method == "POST":
        # to clarify the logged in user is a specialist or a normal user. by default setting as false
        # if it remains false then the logged in user is a normal user else he is a specialist
        role = "user"

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
            role = "specialist"

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
        if role == "user":
            new_user = Users(
                email=email,
                password=hashed_password,
                name=name
            )
            db.session.add(new_user)
            db.session.commit()
            # Log in and authenticate user after adding details to database.
            login_user(new_user)  # Logs in a user by saving their ID in the session.

            # storing the composite user_id in the session to ensure which user is login in . user or admin or specialist
            # eg: user_1 or specilaist_1 or admin_1.the user_id looks like this.
            # it can be taken by the loaduser callback and takes the id form the table of the logged in user.
            session["user_id"] = f"user_{new_user.id}"

        else:
            new_user = Specialist(
                email=email,
                password=hashed_password,
                specialization=request.form.get("specialization"),
                name=name
            )
            db.session.add(new_user)
            db.session.commit()

            # Log in and authenticate user after adding details to database.
            login_user(new_user)  # Logs in a user by saving their ID in the session.

            # storing the composite user_id in the session to ensure which user is login in . user or admin or specialist
            # eg: user_1 or specilaist_1 or admin_1.the user_id looks like this.
            # it can be taken by the loaduser callback and takes the id form the table of the logged in user.
            session["user_id"] = f"specialist_{new_user.id}"

        return redirect(url_for("home", role=role))


@app.route("/login", methods=['POST'])
def login():

    if request.method == "POST":
        # to clarify the logged in user is a specialist or a normal user. by default setting as false
        # if it remains false then the logged in user is a normal user else he is a specialist
        role = "user"

        email = request.form.get("email")
        password = request.form.get("password")
        # this is the one that tells in which form it has came from. there are two forms for login, admin and users
        form_name = request.args.get("form_name")

        # finds the user and admin by email entered
        if form_name and form_name == "admin":
            print("yes")
            # checking that the user is exist, who tries to login
            user = db.session.execute(db.select(AdminUser).where(AdminUser.email == email)).scalar()
            role = "admin"

            user_id = f"admin_{user.id}"  # Composite ID for admin
        else:
            # checking that the logging user is a specialist or a normal user
            # if the radio button tells it is the user. then get the user details from the User table
            if request.form.get("role") == "user":
                user = db.session.execute(db.select(Users).where(Users.email == email)).scalar()
                if user:
                    user_id = f"user_{user.id}"  # Composite ID for user

            # else the user is a specialist so getting the specialist data from the database
            else:
                user = db.session.execute(db.select(Specialist).where(Specialist.email == email)).scalar()
                if user:
                    role = "specialist"
                    user_id = f"specialist_{user.id}"  # Composite ID for specialist


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
            print("yes")
            login_user(user)  # Logs in a user by saving their ID in the session.

            # storing the composite user_id in the session to ensure which user is login in . user or admin or specialist
            # eg: user_1 or specilaist_1 or admin_1.the user_id looks like this.
            # it can be taken by the loaduser callback and takes the id form the table of the logged in user.
            session["user_id"] = user_id

            return redirect(url_for('home', role=role))


@app.route('/logout')
def logout():
    logout_user()  # logout the user by removing the user id from the session
    return redirect(url_for('landingpage'))


# Contact Admin Route
# it is route which is triggered when the user is a specialist and he clicks the contact_admin button shown to him
# here the content from the form is stored in the messages database which is only shown to the admin when he goes to admin panel
@app.route('/contact-admin', methods=['GET', 'POST'])
def contact_admin():

    # if the user is not authenticated then show the login and register page
    if not current_user.is_authenticated:
        return render_template("landingpage.html")

    # if the user is authenticated then the login and register page should not be shown.
    # role is used in base.html
    # contact_admin page rendered. if the user is authenticated then we have current_user. so check current_user with isinstance
    else:
        role = None
        # role is used to show contact_admin for specialist in the index.html. and show the admin name if the role is admin
        # so it is not used for any thing except this one.
        if isinstance(current_user, Specialist):
            role = "specialist"
        if isinstance(current_user, AdminUser):
            role = "admin"

        if request.method == 'POST':
            if request.args.get("form_name") == "soil":  # If Soil Form is submitted
                distributor_name = request.form["distributor_name"]
                soil_name = request.form['soil_name']
                location = request.form['location']
                address = request.form['address']
                nutrients = request.form['nutrients']
                best_suited_crops = request.form['best_suited_crops']
                image = request.form['image']
                number = request.form['number']

                distributor_soil_details = DistributorSoilDetails(distributor_name=distributor_name,
                                                                  soil_name=soil_name,
                                                                  nutrients=nutrients,
                                                                  best_suited_crops=best_suited_crops,
                                                                  image=image,
                                                                  location=location,
                                                                  address=address,
                                                                  contact_number=number
                                                                  )

                db.session.add(distributor_soil_details)
                db.session.commit()
                flash('Soil details added successfully!', 'success')
                # return redirect(url_for("contact_admin"))

            elif request.args.get("form_name") == "crop":   # If Crop Form is submitted
                distributor_name = request.form["distributor_name"]
                crop_name = request.form['crop_name']
                location = request.form['location']
                soil_type = request.form['soil_type']
                address = request.form['address']
                growing_season = request.form['growing_season']
                image = request.form['image']
                number = request.form['number']


                distributor_crop_details = DistributorCropDetails(distributor_name=distributor_name,
                                                                  crop_name=crop_name,
                                                                  soil_type=soil_type,
                                                                  growing_season=growing_season,
                                                                  image=image,
                                                                  location=location,
                                                                  address=address,
                                                                  contact_number=number
                                                                  )

                db.session.add(distributor_crop_details)
                db.session.commit()
                flash('Crop details added successfully!', 'success')

        return render_template('contact_admin.html', role=role, logged_in=current_user.is_authenticated)


# this route is used to show the soil and crop details
@app.route("/details")
def details():
    # if the user is not authenticated then show the login and register page
    if not current_user.is_authenticated:
        return render_template("landingpage.html")

    # if the user is authenticated then the login and register page should not be shown.
    # role is used in base.html
    # contact_admin page rendered. if the user is authenticated then we have current_user. so check current_user with isinstance
    else:
        role = None
        # role is used to show contact_admin for specialist in the index.html. and show the admin name if the role is admin
        # so it is not used for any thing except this one.
        if isinstance(current_user, Specialist):
            role = "specialist"
        if isinstance(current_user, AdminUser):
            role = "admin"

        # getting the name of the soil or crop to fetch it from the db
        name = unquote(request.args.get("name"))
        details_db = db.session.execute(db.select(Details).where(Details.name == name)).scalars().all()

        return render_template('details.html', role=role, distributors=details_db, logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    # if the user is not authenticated then show the login and register page
    if not current_user.is_authenticated:
        return render_template("landingpage.html")

    # if the user is authenticated then the login and register page should not be shown.
    # role is used in base.html
    # contact_admin page rendered. if the user is authenticated then we have current_user. so check current_user with isinstance
    else:
        role = None
        # role is used to show contact_admin for specialist in the index.html. and show the admin name if the role is admin
        # so it is not used for any thing except this one.
        if isinstance(current_user, Specialist):
            role = "specialist"
        if isinstance(current_user, AdminUser):
            role = "admin"

    return render_template('about.html', role=role, logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True)

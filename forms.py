from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, EmailField, FileField
from wtforms.validators import DataRequired, Email, Length, Regexp
from flask_wtf.file import FileAllowed



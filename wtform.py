from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo, ValidationError
from models import User
from passlib.hash import pbkdf2_sha256


def invalid_credentials(form, field):
    """checker"""
    user_enter = form.username.data
    pass_enter = field.data
    user_object = User.query.filter_by(username=user_enter).first()
    if user_object is None:
        raise ValidationError("username or password is incorrect")
    pass_object = User.query.filter_by(password=pass_enter).first()
    if not pbkdf2_sha256.verify(pass_enter, user_object.password):
        raise ValidationError("username or password is incorrect")


class RegistrationForm(FlaskForm):
    """ Registration form"""

    username = StringField('username', validators=[InputRequired(message="Username required"), Length(min=4, max=25,
                                                                                                      message="Username must be between 4 and 25 characters")])
    password = PasswordField('password', validators=[InputRequired(message="Password required"), Length(min=4, max=25,
                                                                                                        message="Password must be between 4 and 25 characters")])
    confirm_pswd = PasswordField('confirm_pswd', validators=[InputRequired(message="Password required"),
                                                             EqualTo('password', message="Passwords must match")])
    submit_button = SubmitField('Create')

    def validate_username(self, username):
        user_object = User.query.filter_by(username=username.data).first()
        if user_object:
            raise ValidationError("username already taken")

    def validate_password(self, password):
        pass_object = User.query.filter_by(password=password.data).first()
        if pass_object:
            raise ValidationError("password already taken")


class LoginForm(FlaskForm):
    """Login form"""

    username = StringField('username', validators=[InputRequired(message="Username Required")])
    password = PasswordField('password', validators=[InputRequired(message="Password Required"), invalid_credentials])
    submit_button = SubmitField('Login')

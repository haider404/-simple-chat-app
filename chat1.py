import os
import requests
from time import localtime, strftime
from flask_login import LoginManager, login_user, current_user, login_required, logout_user

from wtform import *
from models import *

from flask import Flask, jsonify, render_template, request, redirect, url_for, flash
from flask_socketio import SocketIO, emit, send, join_room, leave_room

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET")
socketio = SocketIO(app)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
db = SQLAlchemy(app)

ROOMS = ["FRIENDS AND FAMILY", "BUSINESS", "CODING"]

# config flask_login
login = LoginManager(app)
login.init_app(app)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route("/", methods=["GET", "POST"])
def index():
    reg = RegistrationForm()
    if reg.validate_on_submit():
        username = reg.username.data
        password = reg.password.data

        hash_pass = pbkdf2_sha256.hash(password)

        user = User(username=username, password=hash_pass)
        db.session.add(user)
        db.session.commit()

        flash('please login now', 'success')
        return redirect(url_for('login'))

    return render_template("index.html", form=reg)


@app.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm()

    if login_form.validate_on_submit():
        user_object = User.query.filter_by(username=login_form.username.data).first()
        login_user(user_object)
        return redirect(url_for("chat"))

    return render_template("login.html", form=login_form)


@app.route("/chat", methods=["GET", "POST"])
def chat():
    if not current_user.is_authenticated:
        flash('Please login', 'danger')
        return redirect(url_for('login'))

    return render_template("chat.html", username=current_user.username, rooms=ROOMS)


@app.route("/logout")
def logout():
    logout_user()
    flash('you have been logged out', 'danger')
    return redirect(url_for('login'))


@socketio.on("message")
def on_message(data):
    send({'msg': data['msg'], 'username': data['username'], 'time_stamp': strftime('%b-%d %I:%M%p', localtime())},
         room=data['room'])


@socketio.on('join')
def join(data):
    join_room(data['room'])
    send({'msg': data['username'] + " has joined the " + data['room'] + " room "},
         room=data['room'])


@socketio.on('leave')
def leave(data):
    leave_room(data['room'])
    send({'msg': data['username'] + "  has left the " + data['room'] + " room "},
         room=data['room'])


if __name__ == "__main__":
    socketio.run(app, debug=True)

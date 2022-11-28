import flask_sqlalchemy
import sqlalchemy
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired,Length, ValidationError
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
current_app = Flask(__name__)
current_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db.init_app(current_app)

class User(db.Model, UserMixin):  # table for the database
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20),nullable=False, unique=True)
    password = db.Column(db.String(90),nullable=False)
    with current_app.app_context():
     db.create_all()

bcrypt = Bcrypt(current_app)
#  flask_sqlalchemy.config._ENGINE_OPTIONS = {sqlalchemy.create_engine(url='sqlite:///database.db')}
current_app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False

current_app.config['SECRET_KEY'] = 'ASECRETKEYFORdemo'


login_manager = LoginManager()
login_manager.init_app(current_app)
login_manager.login_view="login"



class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=6, max=12)],
                           render_kw={"placeholder": 'User Name'})
    password = StringField(validators=[InputRequired(), Length(min=16, max=32)],
                           render_kw={"placeholder": 'Password'})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_username= User.query.filterby(username=username).data.first()
        if existing_username:
            raise ValidationError("The username you selected is already in use. Give it another shot.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=6, max=12)],
                           render_kw={"placeholder": 'User Name'})
    password = PasswordField(validators=[InputRequired(), Length(min=16, max=32)],
                           render_kw={"placeholder": 'Password'})
    submit = SubmitField("LogOn")

@current_app.route('/')
def home():
    return render_template('home.html')

@current_app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dadshboard'))
    return render_template('login.html', form=form)

@current_app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

@current_app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@current_app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user= User(username= form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('register.html', form=form)



if __name__ == '__main__':
    current_app.run(debug=True)
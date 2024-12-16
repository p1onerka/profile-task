from flask import Flask, redirect, render_template, request, url_for
import pathlib
import os
import json
import requests
import sys
from flask_login import LoginManager, login_user, login_required
from authlib.integrations.flask_client import OAuth
from sqlalchemy import MetaData 
from flask_sqlalchemy import SQLAlchemy
from pathlib import Path
import shutil
from flask import Flask, redirect, url_for
from flask_dance.contrib.github import make_github_blueprint, github
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user

from config import SQLITE_DATABASE_NAME, SECRET_KEY

app = Flask(__name__, static_folder='static', template_folder='templates', 
            static_url_path='')
#app.secret_key = "5e866465a4b37dc40626ef9e0d01281be3715a20"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + SQLITE_DATABASE_NAME
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_NAME'] = "flaskauth"

convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

metadata = MetaData(naming_convention=convention)
db = SQLAlchemy(metadata=metadata)
db.init_app(app)

#db.app = app
#db.init_app(app)

login_manager = LoginManager(app)
#login_manager.login_view = "login_page"

#login_manager.init_app(app)

github_blueprint = make_github_blueprint(
    client_id="Ov23livGUGj7h22VHE7g",
    client_secret="5e866465a4b37dc40626ef9e0d01281be3715a20",
    redirect_to="github_login"
)
app.register_blueprint(github_blueprint, url_prefix="/github")

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nick = db.Column(db.String(255), nullable=True)
    avatar_uri = db.Column(db.String(512), default='empty.jpg', nullable=False)
    vk_id = db.Column(db.String(255), nullable=True)
    telegram_id = db.Column(db.String(255), nullable=True)

    def __repr__(self) -> str:
        return f"Id={self.id} - Nick={self.nick}"

    def __str__(self) -> str:
        return f"Id={self.id} - Nick={self.nick}"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index_page():
    return render_template('index.html', user=current_user if current_user.is_authenticated else None)

@app.route('/login')
def login_page():
    return render_template('login.html')

'''
@app.route('/auth/vk_auth')
def vk_auth():
    user_code = request.args.get('code')
    if not user_code:
        return redirect(url_for('login_page'))
    response = requests.get(
        'https://oauth.vk.com/access_token?client_id=52797104&client_secret=zE1JE41CD7PhIwyyMrFr&redirect_uri=http://127.0.0.1:5000/auth/vk_auth&code=' + user_code)

    access_token_json = json.loads(response.text)'''

@app.route("/github/login")
def github_login():
    if not github.authorized:
        return redirect(url_for("github.login"))
    resp = github.get("/user")
    github_info = resp.json()
    github_id = str(github_info["id"])
    username = github_info["login"]
    avatar_url = github_info.get("avatar_url", "empty.jpg")

    # Поиск или создание пользователя
    user = User.query.filter_by(vk_id=github_id).first()
    if not user:
        user = User(
            nick=username,
            avatar_uri=avatar_url,
            vk_id=github_id
        )
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))

with app.app_context():
    db.create_all()
    

if __name__ == '__main__':
    #if len(sys.argv) > 1:
    #    if sys.argv[1] == 'init':
    #        init_db(app)
    #else:
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)


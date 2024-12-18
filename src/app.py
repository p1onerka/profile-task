from flask import Flask, redirect, render_template, request, url_for
import os
import requests
from flask_login import LoginManager, login_user
from sqlalchemy import MetaData 
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user

from config import SQLITE_DATABASE_NAME, SECRET_KEY

app = Flask(__name__, static_folder='static', template_folder='templates', 
            static_url_path='')

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

login_manager = LoginManager(app)
login_manager.login_view = 'login'

GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_API_URL = "https://api.github.com/user"

'''
github_blueprint = make_github_blueprint(
    client_id="Ov23livGUGj7h22VHE7g",
    client_secret="5e866465a4b37dc40626ef9e0d01281be3715a20",
    redirect_to="github_login"
)
app.register_blueprint(github_blueprint, url_prefix="/github")'''

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

'''
@app.route('/login')
def login_page():
    return render_template('login.html')'''

'''
@app.route('/auth/vk_auth')
def vk_auth():
    user_code = request.args.get('code')
    if not user_code:
        return redirect(url_for('login_page'))
    response = requests.get(
        'https://oauth.vk.com/access_token?client_id=52797104&client_secret=zE1JE41CD7PhIwyyMrFr&redirect_uri=http://127.0.0.1:5000/auth/vk_auth&code=' + user_code)

    access_token_json = json.loads(response.text)'''

@app.route('/login')
def login():
    github_redirect_url = f"{GITHUB_AUTH_URL}?client_id={GITHUB_CLIENT_ID}&redirect_uri={url_for('callback', _external=True)}"
    return redirect(github_redirect_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return "Authorization failed!", 400

    token_response = requests.post(
        GITHUB_TOKEN_URL,
        headers={"Accept": "application/json"},
        data={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": url_for('callback', _external=True),
        },
    )

    token_data = token_response.json()
    access_token = token_data.get('access_token')
    if not access_token:
        return "Failed to obtain access token!", 400

    user_response = requests.get(
        GITHUB_USER_API_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    user_data = user_response.json()

    if 'id' not in user_data:
        return "Failed to fetch user information!", 400

    github_id = str(user_data['id'])
    user = User.query.filter_by(vk_id=github_id).first()
    if user is None:
        user = User(
            nick=user_data.get('login'),
            avatar_uri=user_data.get('avatar_url'),
            vk_id=github_id,
        )
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))
    

if __name__ == '__main__':
    #if len(sys.argv) > 1:
    #    if sys.argv[1] == 'init':
    #        init_db(app)
    #else:
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)


from flask import Flask, redirect, url_for, session, render_template, request
from authlib.integrations.flask_client import OAuth
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import json
import hashlib
import hmac
import os

load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates', 
            static_url_path='')
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
oauth = OAuth(app)

TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

github = oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50), nullable=False)  # 'google' or 'github'
    provider_id = db.Column(db.String(100), unique=True, nullable=False)  # OAuth unique ID
    name = db.Column(db.String(100), nullable=True)
    username = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(300), nullable=True)  # Avatar URL


@app.route('/', methods=['GET'])
def index():
    user = session.get('user')
    return render_template('index.html', user=user)


@app.route('/login/<provider>')
def login(provider):
    if provider == 'telegram':
        return redirect(url_for('telegram_auth'))
    redirect_uri = url_for('authorize', provider=provider, _external=True)
    return oauth.create_client(provider).authorize_redirect(redirect_uri)


@app.route('/authorize/<provider>')
def authorize(provider):
    if provider == 'telegram':
        return handle_telegram_auth()
    client = oauth.create_client(provider)
    token = client.authorize_access_token()
    user_info = client.get('user').json()
    return save_user_info(provider, user_info)


@app.route('/telegram_auth', methods=['GET'])
def telegram_auth():
    return handle_telegram_auth()


# Function to verify the Telegram auth data
def check_response(data):
    d = data.copy()
    del d['hash']
    d_list = []
    for key in sorted(d.keys()):
        if d[key] is not None:
            d_list.append(f"{key}={d[key]}")
    data_string = '\n'.join(d_list).encode('utf-8')

    secret_key = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode('utf-8')).digest()
    hmac_string = hmac.new(secret_key, data_string, hashlib.sha256).hexdigest()

    return hmac_string == data['hash']


def handle_telegram_auth():
    data = {
        'id': request.args.get('id'),
        'first_name': request.args.get('first_name'),
        'last_name': request.args.get('last_name'),
        'username': request.args.get('username'),
        'photo_url': request.args.get('photo_url'),
        'auth_date': request.args.get('auth_date'),
        'hash': request.args.get('hash')
    }

    # Check if the response is valid
    if not check_response(data):
        return "Invalid authentication", 403

    # If the response is valid, save the user info
    user_info = {
        'provider': 'telegram',
        'id': data['id'],
        'username': data['username'],
        'name': data['first_name'] + ' ' + (data['last_name'] or ''),
        'avatar': data['photo_url']
    }

    # Save user info
    return save_user_info('telegram', user_info)


def save_user_info(provider, user_info):
    # Extract key user info
    provider_id = user_info.get('id')
    username = user_info.get('username')
    name = user_info.get('name')
    avatar = user_info.get('avatar')

    # Check if user exists in the database
    user = User.query.filter_by(provider=provider, provider_id=provider_id).first()
    if not user:
        # Save new user to the database
        user = User(provider=provider, provider_id=provider_id, username=username, name=name, avatar=avatar)
        db.session.add(user)
        db.session.commit()

    # Save user to session
    session['user'] = {'name': user.name, 'avatar': user.avatar}
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


# Initialize the database
initialized = False  # Flag to ensure initialization runs only once


@app.before_request
def init_db_once():
    global initialized
    if not initialized:
        db.create_all()
        initialized = True


if __name__ == '__main__':
    with app.app_context():  # Ensure the app context is available
        db.create_all()      # Create the database tables
    app.run(debug=True)



'''import os
from flask import Flask, render_template, redirect, request, url_for, session
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import hashlib
import hmac
import requests
from config import SQLITE_DATABASE_NAME, SECRET_KEY

# load env variables
load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates', 
            static_url_path='')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + SQLITE_DATABASE_NAME
app.config['SECRET_KEY'] = SECRET_KEY

db = SQLAlchemy()
db.init_app(app)

# user model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegram_id = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    username = db.Column(db.String(50))

# main page
@app.route('/')
def index():
    return render_template('index.html')

# telegram auth'''
'''
@app.route('/login/telegram', methods=['GET'])
def login_telegram():
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    secret_key = hashlib.sha256(bot_token.encode()).digest()

    # check request parameters
    auth_data = request.args.to_dict()
    auth_hash = auth_data.pop('hash', None)

    data_check_string = '\n'.join(f"{k}={v}" for k, v in sorted(auth_data.items()))
    calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    if calculated_hash != auth_hash:
        return "incorrect auth", 403

    telegram_id = auth_data['id']
    first_name = auth_data.get('first_name', '')
    last_name = auth_data.get('last_name', '')
    username = auth_data.get('username', '')

    # save user in db
    user = User.query.filter_by(telegram_id=telegram_id).first()
    if not user:
        user = User(
            telegram_id=telegram_id,
            first_name=first_name,
            last_name=last_name,
            username=username
        )
        db.session.add(user)
        db.session.commit()

    # save data in session
    session['user'] = {
        'telegram_id': telegram_id,
        'first_name': first_name,
        'username': username
    }
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)'''

'''
from flask import Flask, redirect, render_template, request, url_for, request
import os
import hmac
import hashlib
from dotenv import load_dotenv
import requests
from flask_login import LoginManager, login_user
from sqlalchemy import MetaData 
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user

from config import SQLITE_DATABASE_NAME, SECRET_KEY

load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates', 
            static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + SQLITE_DATABASE_NAME
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False #True?
app.config['TELEGRAM_BOT_TOKEN'] = os.getenv('TELEGRAM_BOT_TOKEN')
#app.config['SECRET_KEY'] = SECRET_KEY
#app.config['SESSION_COOKIE_NAME'] = "flaskauth"

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

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nick = db.Column(db.String(255), nullable=True)
    avatar_uri = db.Column(db.String(512), default='empty.jpg', nullable=False)
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
def login():
    github_redirect_url = f"{GITHUB_AUTH_URL}?client_id={GITHUB_CLIENT_ID}&redirect_uri={url_for('callback', _external=True)}"
    return redirect(github_redirect_url)

@app.route('/login/telegram', methods=['POST'])
def telegram_login():
    data = request.form.to_dict()
    auth_data = {k: v for k, v in data.items() if k != 'hash'}

    token = app.config['TELEGRAM_BOT_TOKEN']
    secret = hashlib.sha256(token.encode()).digest()
    check_hash = hmac.new(secret, "\n".join(f"{k}={v}" for k, v in sorted(auth_data.items())).encode(), hashlib.sha256).hexdigest()
    if check_hash != data.get('hash'):
        return "Invalid data signature", 400

    telegram_id = data['id']
    nick = data.get('username', f"{data.get('first_name', '')} {data.get('last_name', '')}".strip())
    avatar_uri = data.get('photo_url', 'empty.jpg')

    user = User.query.filter_by(telegram_id=telegram_id).first()
    if user is None:
        user = User(telegram_id=telegram_id, nick=nick, avatar_uri=avatar_uri)
        db.session.add(user)
    else:
        user.nick = nick
        user.avatar_uri = avatar_uri
    db.session.commit()

    login_user(user)
    return redirect(url_for('index'))

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
'''
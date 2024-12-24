from flask import Flask, redirect, url_for, session, render_template, request
from authlib.integrations.flask_client import OAuth
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
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

initialized = False 

@app.before_request
def init_db():
    global initialized
    if not initialized:
        db.create_all()
        initialized = True

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
    provider = db.Column(db.String(50), nullable=False)
    provider_id = db.Column(db.String(100), unique=True,
                            nullable=False) 
    name = db.Column(db.String(100), nullable=True)
    username = db.Column(db.String(100), nullable=True)

def save_user(provider, user_info):
    provider_id = user_info.get('id')
    username = user_info.get(
        'username') if provider == 'telegram' else user_info.get('login')
    name = user_info.get('name') or user_info.get(
        'login')

    user = User.query.filter_by(
        provider=provider, provider_id=provider_id).first()
    if not user:
        user = User(provider=provider, provider_id=provider_id,
                    username=username, name=name)
        db.session.add(user)
        db.session.commit()

    session['user'] = {'name': user.name, 'username': user.username,
                       'provider': user.provider}
    return redirect(url_for('index'))

@app.route('/', methods=['GET', 'POST'])
def index():
    user = session.get('user')
    return render_template('index.html', user=user)

@app.route('/login/<provider>')
def login(provider):
    redirect_uri = url_for('authorize', provider=provider, _external=True)
    return oauth.create_client(provider).authorize_redirect(redirect_uri)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/authorize/<provider>')
def authorize(provider):

    if provider == 'telegram':
        return auth_tg()
    client = oauth.create_client(provider)
    token = client.authorize_access_token()
    user_info = client.get('user').json()
    return save_user(provider, user_info)

@app.route('/telegram_auth', methods=['GET', 'POST'])
def telegram_auth():
    return auth_tg()

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


def auth_tg():
    data = {
        'id': request.args.get('id'),
        'first_name': request.args.get('first_name'),
        'last_name': request.args.get('last_name'),
        'username': request.args.get('username'),
        'photo_url': request.args.get('photo_url'),
        'auth_date': request.args.get('auth_date'),
        'hash': request.args.get('hash')
    }

    if not check_response(data):
        return "Invalid authentication", 403

    user_info = {
        'provider': 'telegram',
        'id': data['id'],
        'username': data['username'],
        'first_name': data['first_name'],
        'last_name': data['last_name']
    }

    return save_user('telegram', user_info)

if __name__ == '__main__':
    with app.app_context(): 
        db.create_all()     
    app.run(debug=True)
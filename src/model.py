'''
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    nick = db.Column(db.String(255), nullable=True)
    avatar_uri = db.Column(db.String(512), nullable=True)

def init_db():
    db.drop_all()
    db.create_all() '''

'''
from sqlalchemy import MetaData 
from flask_sqlalchemy import SQLAlchemy
from pathlib import Path
import shutil

from config import SQLITE_DATABASE_NAME
from config import SQLITE_DATABASE_BACKUP_NAME


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    nick = db.Column(db.String(255), nullable=True)
    avatar_uri = db.Column(db.String(512), default='empty.jpg', nullable=False)
    vk_id = db.Column(db.String(255), nullable=True)
    telegram_id = db.Column(db.String(255), nullable=True)

    def __repr__(self) -> str:
        return f"Id={self.id} - Nick={self.nick}"
    def __str__(self) -> str:
        return f"Id={self.id} - Nick={self.nick}"
    
#if DB exists, backup it
def init_db(app):
    db_file = Path('instance/' + SQLITE_DATABASE_NAME)
    if db_file.is_file():
        shutil.copyfile('instance/' + SQLITE_DATABASE_NAME, 
                        SQLITE_DATABASE_BACKUP_NAME)
    with app.app_context():
        print("Create DB: " + app.config['SQLALCHEMY_DATABASE_URI'])
        db.session.commit()
        db.drop_all()
        db.create_all()
'''
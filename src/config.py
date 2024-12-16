'''
import os
import pathlib

SQLITE_DATABASE_NAME = 'flask_auth.db'
SECRET_KEY_FILE = os.path.join(pathlib.Path(__file__).parent, "flask_auth.conf")

if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as file:
        SECRET_KEY = file.read().strip()
else:
    SECRET_KEY = os.urandom(16).hex()'''


import os
import pathlib

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
SQLITE_DATABASE_NAME = 'flask_auth.db'
SQLITE_DATABASE_BACKUP_NAME = 'flask_auth.db.bak'
SECRET_KEY_FILE = os.path.join(pathlib.Path(__file__).parent, "flask_auth.conf")

SECRET_KEY = ''

'''
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as file:
        SECRET_KEY = file.read().rstrip()
else:
    print ("There is no SECRET_KEY_FILE, generate random SECRET_KEY")
    SECRET_KEY = os.urandom(16).hex'''

if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as file:
        SECRET_KEY = file.read().strip()  # Удаляем лишние пробелы и символы новой строки
else:
    print("There is no SECRET_KEY_FILE, generating a random SECRET_KEY")
    SECRET_KEY = os.urandom(16).hex()  # Генерируем ключ и преобразуем его в строку
    # Сохраняем ключ в файл, чтобы использовать его повторно
    with open(SECRET_KEY_FILE, 'w') as file:
        file.write(SECRET_KEY)

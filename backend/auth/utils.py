import bcrypt
from flask_jwt_extended import create_access_token
from datetime import timedelta


def hash_password(password):

    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


def generate_token(identity):
    return create_access_token(identity=identity, expires_delta=timedelta(hours=2))

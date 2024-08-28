#!/usr/bin/env python
import os
import time
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

# inicialização
app = Flask(__name__)
app.config['SECRET_KEY'] = 'p3nsanumasenhabraba'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

################################
## Definições do Database 
# Tabela users
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(128))

################################
## Métodos
# Gera o hash do password e descarta o password
    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

# Verifica o password
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

# gerar token de auth único para o tempo com SECRET_KEY
    def generate_auth_token(self, expires_in=22000):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

# Verifica a autenticidade do token
    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])

# Define o usuário como logado após verificar método de auth
@auth.verify_password
def verify_password(username_or_token, password):
    # primeiro tenta autenticar com o token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # tenta autenticar com password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

################################
## Endpoints
# Insere um novo usuário
@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # SEM ARGUMENTOS
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # USUARIO EXISTENTE
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})

# Retorna o username caso o id existir
@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})

# Define o endpoint que chama a criação e retorno do token
@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(22000)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})

################################
### TO-DO: Retorna registros de ambientes
################################
# Acessa o recurso protegido
@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})

################################
## Global variables
# Cria database caso não exista
if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)
#   app.run(debug=False)        
from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'mysecret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'myjwtsecret')

# Initialize extensions
db = SQLAlchemy(app)
api = Api(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)

# User Resource Parsers
user_parser = reqparse.RequestParser()
user_parser.add_argument('username', type=str, required=True, help="Username cannot be blank!")
user_parser.add_argument('password', type=str, required=True, help="Password cannot be blank!")

# Item Resource Parsers
item_parser = reqparse.RequestParser()
item_parser.add_argument('name', type=str, required=True, help="Name cannot be blank!")
item_parser.add_argument('price', type=float, required=True, help="Price cannot be blank!")

# Resources
class UserRegister(Resource):
    def post(self):
        data = user_parser.parse_args()
        if User.query.filter_by(username=data['username']).first():
            return {'message': 'User already exists'}, 400
        
        user = User(username=data['username'])
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()
        
        return {'message': 'User created successfully'}, 201

class UserLogin(Resource):
    def post(self):
        data = user_parser.parse_args()
        user = User.query.filter_by(username=data['username']).first()
        
        if user and user.check_password(data['password']):
            access_token = create_access_token(identity=user.id)
            return {'access_token': access_token}, 200
        
        return {'message': 'Invalid credentials'}, 401

class ItemResource(Resource):
    @jwt_required()
    def get(self, item_id):
        item = Item.query.get_or_404(item_id)
        return {'id': item.id, 'name': item.name, 'price': item.price}, 200

    @jwt_required()
    def delete(self, item_id):
        item = Item.query.get_or_404(item_id)
        db.session.delete(item)
        db.session.commit()
        return {'message': 'Item deleted'}, 200

    @jwt_required()
    def put(self, item_id):
        data = item_parser.parse_args()
        item = Item.query.get_or_404(item_id)
        
        item.name = data['name']
        item.price = data['price']
        db.session.commit()
        
        return {'id': item.id, 'name': item.name, 'price': item.price}, 200

class ItemList(Resource):
    @jwt_required()
    def get(self):
        items = Item.query.all()
        return [{'id': item.id, 'name': item.name, 'price': item.price} for item in items], 200

    @jwt_required()
    def post(self):
        data = item_parser.parse_args()
        if Item.query.filter_by(name=data['name']).first():
            return {'message': 'Item already exists'}, 400
        
        item = Item(name=data['name'], price=data['price'])
        db.session.add(item)
        db.session.commit()
        
        return {'id': item.id, 'name': item.name, 'price': item.price}, 201

# Add resource routes
api.add_resource(UserRegister, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(ItemList, '/items')
api.add_resource(ItemResource, '/items/<int:item_id>')

# Run the application
if __name__ == '__main__':
    # Create database tables before running the app
    with app.app_context():
        db.create_all()

    app.run(debug=True)

from flask import request, session
from flask_restful import Resource
from marshmallow.exceptions import ValidationError

from config import app, db, api
from models import User, UserSchema

user_schema = UserSchema()
users_schema = UserSchema(many=True)

@app.route('/')
def index():
  return '<h1>Project Server</h1>'

class Register(Resource):
  def post(self):
    try:
      data = request.get_json()
      if not data or not all(k in data for k in ['username', 'email', 'password']):
        return {'error': 'Missing required fields: username, email, and password are required'}, 400

      if User.query.filter_by(username=data['username']).first():
        return {'error': 'Username already exists.'}, 400
      
      if User.query.filter_by(email=data['email']).first():
        return {'error': 'Email already exists.'}, 400
      
      new_user = users_schema.load(data) 
      db.session.add(new_user)
      db.session.commit()
      session['user_id'] = new_user.id

      return user_schema.dump(new_user), 201
    
    except ValidationError as ve:
      return {'error': str(ve)}, 400
    
    except Exception as e:
      print(f'Registration error: {str(e)}')
      return {'error': f'An error occured during registration: {str(e)}'}, 500
    
api.add_resource(Register, '/register')

class Login(Resource):
  def post(self):
    try:
      data = request.get_json()
      if not data or all(k in data for k in ['username', 'email', 'password']):
        return {'error': 'Missing required fields.'}, 400
      
      user = User.query.filter_by(username=data['username']).first()
      if not user:
        return {'message': 'Invalid credentials'}, 401
      
      if not user._password_hash:
        return {'message': 'Invalid credentials'}, 401
      
      if user.authenticate(data['password']):
        session['user_id'] = user.id
        return user_schema.dump(user), 200
      
      return {'message': 'Invalid credentials'}, 401
    
    except Exception as e:
      return {'error': str(e)}, 500
    
api.add_resource(Login, '/login')

class CheckSession(Resource):
  def get(self):
    user_id = session.get('user_id')
    if user_id:
      user = db.session.get(User, user_id)
      if user:
        user_data = user_schema.dump(user)
        return user_data, 200
      return {'error': 'Not authenticated.'}, 401
    return {'error': 'Not authenticated.'}, 401

api.add_resource(CheckSession, '/check_session')

class Logout(Resource):
  def delete(self):
    session.pop('user_id', None)
    return {}, 204
  
api.add_resource(Logout, '/logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
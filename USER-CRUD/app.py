# import datetime

# import bcrypt
# import jwt
# from flask import Flask, jsonify, request
# from flask_cors import CORS
# from pymongo import MongoClient
# from pymongo.errors import ConnectionFailure

# app = Flask(__name__)
# CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:5500"}})  # Restrict CORS to frontend origin

# # MongoDB setup
# try:
#     client = MongoClient('mongodb://localhost:27017', serverSelectionTimeoutMS=5000)
#     client.server_info()  # Test connection
#     db = client['user_management']
#     users_collection = db['users']
#     print("Connected to MongoDB successfully")
# except ConnectionFailure as e:
#     print(f"MongoDB connection failed: {e}")
#     exit(1)

# # JWT secret key (use environment variables in production)
# JWT_SECRET = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidXNlciIsIm5hbWUiOiJKb2huIERvZSIsImV4cCI6MTc1NTc1ODAyMSwic3ViIjoidXNlci1pZCIsImF1ZCI6InlvdXItYXVkaWVuY2UiLCJpc3MiOiJ5b3VyLWFwcCIsImlhdCI6MTc1NTY3MTYyMX0.v0YeD0U9ql7mTRVfUQnSGsrydSSj6NQw1Zs33mLH7NA'

# def verify_token(token):
#     try:
#         decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
#         return decoded['user_id']
#     except jwt.InvalidTokenError as e:
#         print(f"Token verification failed: {e}")
#         return None

# @app.route('/register', methods=['POST'])
# def register():
#     try:
#         data = request.get_json()
#         name = data.get('name')
#         email = data.get('email')
#         password = data.get('password')
        
#         if not name or not email or not password:
#             return jsonify({'error': 'Name, email, and password are required'}), 400
        
#         # Check if email already exists
#         if users_collection.find_one({'email': email}):
#             return jsonify({'error': 'Email already exists'}), 400
        
#         # Hash password
#         hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
#         # Insert user
#         user = {
#             'name': name,
#             'email': email,
#             'password': hashed_password
#         }
#         result = users_collection.insert_one(user)
        
#         # Generate JWT
#         try:
#             token = jwt.encode({
#                 'user_id': str(result.inserted_id),
#                 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
#             }, JWT_SECRET, algorithm='HS256')
#         except Exception as e:
#             print(f"JWT encoding failed: {e}")
#             return jsonify({'error': 'Failed to generate token'}), 500
        
#         return jsonify({'token': token, 'name': name, 'email': email}), 201
#     except Exception as e:
#         print(f"Error in register: {e}")
#         return jsonify({'error': 'Internal server error'}), 500

# @app.route('/login', methods=['POST'])
# def login():
#     try:
#         data = request.get_json()
#         email = data.get('email')
#         password = data.get('password')
        
#         if not email or not password:
#             return jsonify({'error': 'Email and password are required'}), 400
        
#         user = users_collection.find_one({'email': email})
#         if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
#             return jsonify({'error': 'Invalid email or password'}), 401
        
#         # Generate JWT
#         try:
#             token = jwt.encode({
#                 'user_id': str(user['_id']),
#                 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
#             }, JWT_SECRET, algorithm='HS256')
#         except Exception as e:
#             print(f"JWT encoding failed: {e}")
#             return jsonify({'error': 'Failed to generate token'}), 500
        
#         return jsonify({'token': token, 'name': user['name'], 'email': user['email']})
#     except Exception as e:
#         print(f"Error in login: {e}")
#         return jsonify({'error': 'Internal server error'}), 500

# @app.route('/users', methods=['GET'])
# def get_users():
#     try:
#         token = request.headers.get('Authorization')
#         if not token or not token.startswith('Bearer '):
#             return jsonify({'error': 'Token is missing or invalid'}), 401
        
#         user_id = verify_token(token.split(' ')[1])
#         if not user_id:
#             return jsonify({'error': 'Invalid token'}), 401
        
#         users = list(users_collection.find({}, {'password': 0}))  # Exclude password field
#         for user in users:
#             user['_id'] = str(user['_id'])  # Convert ObjectId to string
#         return jsonify(users)
#     except Exception as e:
#         print(f"Error in get_users: {e}")
#         return jsonify({'error': 'Internal server error'}), 500

# @app.route('/users', methods=['POST'])
# def create_user():
#     try:
#         token = request.headers.get('Authorization')
#         if not token or not token.startswith('Bearer '):
#             return jsonify({'error': 'Token is missing or invalid'}), 401
        
#         user_id = verify_token(token.split(' ')[1])
#         if not user_id:
#             return jsonify({'error': 'Invalid token'}), 401
        
#         data = request.get_json()
#         name = data.get('name')
#         email = data.get('email')
        
#         if not name or not email:
#             return jsonify({'error': 'Name and email are required'}), 400
        
#         if users_collection.find_one({'email': email}):
#             return jsonify({'error': 'Email already exists'}), 400
        
#         user = {'name': name, 'email': email}
#         result = users_collection.insert_one(user)
#         user['_id'] = str(result.inserted_id)
#         return jsonify(user), 201
#     except Exception as e:
#         print(f"Error in create_user: {e}")
#         return jsonify({'error': 'Internal server error'}), 500

# @app.route('/users/<id>', methods=['PUT'])
# def update_user(id):
#     try:
#         token = request.headers.get('Authorization')
#         if not token or not token.startswith('Bearer '):
#             return jsonify({'error': 'Token is missing or invalid'}), 401
        
#         user_id = verify_token(token.split(' ')[1])
#         if not user_id:
#             return jsonify({'error': 'Invalid token'}), 401
        
#         data = request.get_json()
#         name = data.get('name')
#         email = data.get('email')
        
#         if not name or not email:
#             return jsonify({'error': 'Name and email are required'}), 400
        
#         from bson import ObjectId
#         existing_user = users_collection.find_one({'email': email, '_id': {'$ne': ObjectId(id)}})
#         if existing_user:
#             return jsonify({'error': 'Email already exists'}), 400
        
#         result = users_collection.update_one(
#             {'_id': ObjectId(id)},
#             {'$set': {'name': name, 'email': email}}
#         )
#         if result.matched_count == 0:
#             return jsonify({'error': 'User not found'}), 404
        
#         return jsonify({'_id': id, 'name': name, 'email': email})
#     except Exception as e:
#         print(f"Error in update_user: {e}")
#         return jsonify({'error': 'Internal server error'}), 500

# @app.route('/users/<id>', methods=['DELETE'])
# def delete_user(id):
#     try:
#         token = request.headers.get('Authorization')
#         if not token or not token.startswith('Bearer '):
#             return jsonify({'error': 'Token is missing or invalid'}), 401
        
#         user_id = verify_token(token.split(' ')[1])
#         if not user_id:
#             return jsonify({'error': 'Invalid token'}), 401
        
#         from bson import ObjectId
#         result = users_collection.delete_one({'_id': ObjectId(id)})
#         if result.deleted_count == 0:
#             return jsonify({'error': 'User not found'}), 404
        
#         return jsonify({'message': 'User deleted'})
#     except Exception as e:
#         print(f"Error in delete_user: {e}")
#         return jsonify({'error': 'Internal server error'}), 500

# if __name__ == '__main__':
#     app.run(debug=True)


from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import jwt
import bcrypt
import datetime
from bson import ObjectId

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:5500"}})

# MongoDB setup
try:
    client = MongoClient('mongodb://localhost:27017', serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client['user_management']
    users_collection = db['users']
    print("Connected to MongoDB successfully")
except ConnectionFailure as e:
    print(f"MongoDB connection failed: {e}")
    exit(1)

# JWT secret key (use environment variables in production)
JWT_SECRET = 'your-secret-key'

def verify_token(token):
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return {'user_id': decoded['user_id'], 'isAdmin': decoded.get('isAdmin', False)}
    except jwt.InvalidTokenError as e:
        print(f"Token verification failed: {e}")
        return None

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        isAdmin = data.get('isAdmin', False)
        
        if not name or not email or not password:
            return jsonify({'error': 'Name, email, and password are required'}), 400
        
        if users_collection.find_one({'email': email}):
            return jsonify({'error': 'Email already exists'}), 400
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'isAdmin': isAdmin
        }
        result = users_collection.insert_one(user)
        
        try:
            token = jwt.encode({
                'user_id': str(result.inserted_id),
                'isAdmin': isAdmin,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, JWT_SECRET, algorithm='HS256')
        except Exception as e:
            print(f"JWT encoding failed: {e}")
            return jsonify({'error': 'Failed to generate token'}), 500
        
        return jsonify({'token': token, 'name': name, 'email': email, 'isAdmin': isAdmin}), 201
    except Exception as e:
        print(f"Error in register: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = users_collection.find_one({'email': email})
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        try:
            token = jwt.encode({
                'user_id': str(user['_id']),
                'isAdmin': user.get('isAdmin', False),
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, JWT_SECRET, algorithm='HS256')
        except Exception as e:
            print(f"JWT encoding failed: {e}")
            return jsonify({'error': 'Failed to generate token'}), 500
        
        return jsonify({'token': token, 'name': user['name'], 'email': user['email'], 'isAdmin': user.get('isAdmin', False)})
    except Exception as e:
        print(f"Error in login: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/profile', methods=['GET'])
def get_profile():
    try:
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token is missing or invalid'}), 401
        
        decoded = verify_token(token.split(' ')[1])
        if not decoded:
            return jsonify({'error': 'Invalid token'}), 401
        
        user = users_collection.find_one({'_id': ObjectId(decoded['user_id'])}, {'password': 0})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user['_id'] = str(user['_id'])
        return jsonify(user)
    except Exception as e:
        print(f"Error in get_profile: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/profile', methods=['PUT'])
def update_profile():
    try:
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token is missing or invalid'}), 401
        
        decoded = verify_token(token.split(' ')[1])
        if not decoded:
            return jsonify({'error': 'Invalid token'}), 401
        
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        
        if not name or not email:
            return jsonify({'error': 'Name and email are required'}), 400
        
        existing_user = users_collection.find_one({'email': email, '_id': {'$ne': ObjectId(decoded['user_id'])}})
        if existing_user:
            return jsonify({'error': 'Email already exists'}), 400
        
        result = users_collection.update_one(
            {'_id': ObjectId(decoded['user_id'])},
            {'$set': {'name': name, 'email': email}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'_id': str(decoded['user_id']), 'name': name, 'email': email})
    except Exception as e:
        print(f"Error in update_profile: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/users', methods=['GET'])
def get_users():
    try:
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token is missing or invalid'}), 401
        
        decoded = verify_token(token.split(' ')[1])
        if not decoded or not decoded['isAdmin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        users = list(users_collection.find({}, {'password': 0}))
        for user in users:
            user['_id'] = str(user['_id'])
        return jsonify(users)
    except Exception as e:
        print(f"Error in get_users: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/users', methods=['POST'])
def create_user():
    try:
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token is missing or invalid'}), 401
        
        decoded = verify_token(token.split(' ')[1])
        if not decoded or not decoded['isAdmin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        isAdmin = data.get('isAdmin', False)
        
        if not name or not email:
            return jsonify({'error': 'Name and email are required'}), 400
        
        if users_collection.find_one({'email': email}):
            return jsonify({'error': 'Email already exists'}), 400
        
        user = {'name': name, 'email': email, 'isAdmin': isAdmin}
        result = users_collection.insert_one(user)
        user['_id'] = str(result.inserted_id)
        return jsonify(user), 201
    except Exception as e:
        print(f"Error in create_user: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/users/<id>', methods=['PUT'])
def update_user(id):
    try:
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token is missing or invalid'}), 401
        
        decoded = verify_token(token.split(' ')[1])
        if not decoded or not decoded['isAdmin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        isAdmin = data.get('isAdmin', False)
        
        if not name or not email:
            return jsonify({'error': 'Name and email are required'}), 400
        
        existing_user = users_collection.find_one({'email': email, '_id': {'$ne': ObjectId(id)}})
        if existing_user:
            return jsonify({'error': 'Email already exists'}), 400
        
        result = users_collection.update_one(
            {'_id': ObjectId(id)},
            {'$set': {'name': name, 'email': email, 'isAdmin': isAdmin}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'_id': id, 'name': name, 'email': email, 'isAdmin': isAdmin})
    except Exception as e:
        print(f"Error in update_user: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/users/<id>', methods=['DELETE'])
def delete_user(id):
    try:
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token is missing or invalid'}), 401
        
        decoded = verify_token(token.split(' ')[1])
        if not decoded or not decoded['isAdmin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        result = users_collection.delete_one({'_id': ObjectId(id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'message': 'User deleted'})
    except Exception as e:
        print(f"Error in delete_user: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/users/<id>/password', methods=['PUT'])
def change_user_password(id):
    try:
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token is missing or invalid'}), 401
        
        decoded = verify_token(token.split(' ')[1])
        if not decoded or not decoded['isAdmin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        new_password = data.get('new_password')
        
        if not new_password:
            return jsonify({'error': 'New password is required'}), 400
        
        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        # Update the user's password
        result = users_collection.update_one(
            {'_id': ObjectId(id)},
            {'$set': {'password': hashed_password}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'message': 'Password updated successfully'})
    except Exception as e:
        print(f"Error in change_user_password: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, request, jsonify,send_from_directory
from flask_cors import CORS
import json
from datetime import datetime, time
from werkzeug.utils import secure_filename
from db_util import insert_bindata, insert_user, get_user, update_user, update_password, save_profile_picture
from data_auth import authenticate_user
from google.auth.transport import requests
from google.oauth2 import id_token
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
import os
import logging
from ml_script import update_predictions

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:3000"}})

app.config['JWT_SECRET_KEY'] = os.urandom(24)
jwt = JWTManager(app)

@app.route('/data', methods=['POST', 'GET'])
def receive_data():
    if request.method == 'POST':
        data = request.json
        print("Received data:", data)

        with open("sensor_data.json", "a") as f:
            json.dump(data, f)
            f.write("\n")

        if insert_bindata(data):
            return "Sensor data saved"
        else:
            return "Error: error saving sensor data  ", 500


# handle registration
@app.route('/register', methods=['POST', 'GET'])
def register():
    try:
        data = request.get_json()
        print("Received data:", data)

        response, status_code = insert_user(data)

        if status_code == 200:
            username = data.get('username')
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token, username=username), 200

        return jsonify(response), status_code

    except Exception as e:
        return jsonify({"message": "Internal server error"}), 500


# handle login
@app.route('/', methods=['POST'])
def login():
    try:
        data = request.get_json()
        print("Received data:", data)

        response, status_code = authenticate_user(data)

        if status_code == 200:
            username = data.get('username')
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token, username=username), 200

        return jsonify(response), status_code

    except Exception as e:
        logger.error("Error in /login route: %s", e)
        return jsonify({"message": "Internal server error"}), 500


# handle google login
@app.route('/google-login', methods=['POST'])
def handle_google_login():
    token = request.json.get('token')
    print(f"Received token: {token}")
    logger.debug("Received token: %s", token)

    try:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(),
                                              "967460610118-g4oul1g5umkiu6heanm2ornah4hektvu.apps.googleusercontent.com")
        print(f"idinfo: {idinfo}")
        logger.debug("idinfo: %s", idinfo)

        userid = idinfo['sub']
        email = idinfo.get('email')
        name = idinfo.get('name')

        user_data = {
            'email': email,
            'username': name,
            'password': None,
            'phone': ''
        }

        # Check if user already exists
        existing_user = get_user(name)
        if existing_user:
            username = name
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token, username=username), 200
            # return jsonify({"message": "Login successful and user registered", "name": name})

        response, status_code = insert_user(user_data)
        if status_code == 200:
            username = name
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token, username=username), 200
            # return jsonify({"message": "Login successful and user registered", "name": name}), status_code

        else:
            return jsonify(response), status_code

    except ValueError:
        logger.debug("Invalid token")
        print("Invalid token")
        return jsonify({"message": "Invalid token"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    return jsonify({"message": "Logged out successfully"}), 200


# get user (editProfile)
@app.route('/user', methods=['GET'])
@jwt_required()
def get_user_route():
    username = get_jwt_identity()

    if username:
        user_data = get_user(username)
        logger.debug('You are authenticated!')
        print('You are authenticated!')

        if user_data:
            print(user_data)
            return jsonify(user_data), 200
        else:
            return jsonify({"error": "User not found"}), 404
    else:
        return jsonify({"error": "Not logged in"}), 401


# Update user
@app.route('/updateuser', methods=['POST'])
@jwt_required()
def update_user_route():
    current_username = get_jwt_identity()

    if not current_username:
        return jsonify({"error": "Not logged in"}), 401

    user_data = get_user(current_username)

    if not user_data:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()

    # updated_data = {
    #     'username': data.get('username', user_data['username']),
    #     'email': data.get('email', user_data['email']),
    #     'phone': data.get('phone', user_data['phone'])
    # }

    response, status_code = update_user(data, current_username)

    if status_code == 200:
        new_token = create_access_token(identity=data.get('username', current_username))
        return jsonify(response), status_code, {'Authorization': f'Bearer {new_token}'}

    return jsonify(response), status_code

@app.route('/updatepwd', methods=['POST'])
@jwt_required()
def update_pwd():
    username = get_jwt_identity()
    data = request.get_json()

    data['username'] = username
    password = data.get('password')
    new_password = data.get('newPassword')
    confirm_password = data.get('confirmPassword')

    if authenticate_user(data):
        if new_password != confirm_password:
            return jsonify({"message": "New passwords do not match"}), 400

        else:
            response, status_code = update_password(data)
            # return jsonify({"message": "New passwords do not match"}), 400

        if status_code == 200:
            return jsonify(response), status_code

def convert_to_serializable(data):
    if isinstance(data, list):
        return [convert_to_serializable(item) for item in data]
    elif isinstance(data, dict):
        return {key: convert_to_serializable(value) for key, value in data.items()}
    elif isinstance(data, (datetime, time)):
        return data.strftime('%Y-%m-%d %H:%M:%S') if isinstance(data, datetime) else data.strftime('%H:%M:%S')
    return data

@app.route('/gettimes', methods=['GET'])
def get_predictions():
    response = update_predictions()
    return jsonify(response)

UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/uploadprofilepicture', methods=['POST'])
@jwt_required()
def upload_profile_picture():
    username = get_jwt_identity()

    if 'profilePicture' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['profilePicture']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        file_url = os.path.join('/' + app.config['UPLOAD_FOLDER'], filename)

        save_profile_picture(username, file_url)

        return jsonify({'file_url': file_url}), 200
    else:
        return jsonify({'error': 'File type not allowed'}), 400

if __name__ == "__main__":
    app.run(debug=True)










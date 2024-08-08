from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime, timedelta
from googleapiclient.errors import HttpError
from werkzeug.utils import secure_filename
from google.auth.transport import requests
from google.oauth2 import id_token
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pandas as pd
import json
import random
import time
import logging
import os
import base64
from ml_scripts.predictions import update_predictions,  linear_regression_decision
from db_util import insert_bindata, insert_user, get_user, update_user, update_password, save_profile_picture, \
    retrieve_bindata, fetch_bindata_byid, get_collectors, insert_collector, deleteCollector, find_collector_by_email, \
    updateCollector, getBinMetadata
from data_auth import authenticate_user


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
        response, status_code = insert_user(data)

        if status_code == 200:
            username = data.get('username')
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token, username=username), 200

        return jsonify(response), status_code

    except Exception as e:
        return jsonify({"message": "Internal server error"}), 500


# handle login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
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

        if user_data:
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
    response, status_code = update_user(data, current_username)

    if status_code == 200:
        new_token = create_access_token(identity=data.get('username', current_username))
        return jsonify(response), status_code, {'Authorization': f'Bearer {new_token}'}

    return jsonify(response), status_code

@app.route('/update-password', methods=['POST'])
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
        if status_code == 200:
            return jsonify(response), status_code

@app.route('/gettimes', methods=['GET'])
def get_predictions():
    response = update_predictions()
    return jsonify(response)

@app.route('/decisions', methods=['GET'])
def get_decisions():
    response = linear_regression_decision()
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


@app.route('/charts/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)


# okay
@app.route('/api/waste-data', methods=['GET'])
def get_waste_data():
    df = retrieve_bindata()

    df['timestamp'] = pd.to_datetime(df['timestamp'])

    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    bin_id = request.args.get('bin_id')

    if start_date and end_date:
        mask = (df['timestamp'] >= start_date) & (df['timestamp'] <= end_date)
        filtered_df = df[mask]
    else:
        filtered_df = df

    if bin_id:
        filtered_df = filtered_df[filtered_df['bin_no'] == bin_id]

    result = filtered_df.to_dict(orient='records')
    return jsonify(result)


@app.route('/waste-data', methods=['GET'])
def get_bin_data():
    df = retrieve_bindata()

    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df_list = df.to_dict(orient='records')
    return jsonify(df_list)

# @app.route('/getbindata', methods=['GET'])
# def get_getbindata():
#     response = show_bindata()
#     return jsonify(response)

@app.route('/historical-data', methods=['GET'])
def get_bin_data_byid():
    bin_no = request.args.get('bin_no')
    if not bin_no:
        return jsonify({"error": "Missing bin_no parameter"}), 400

    end_date = datetime.now()
    start_date = end_date - timedelta(days=28)

    df = fetch_bindata_byid(bin_no, start_date, end_date)
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['time'] = df['timestamp'].dt.strftime('%H:%M:%S')
    df_list = df.to_dict(orient='records')
    return jsonify(df_list)

# Simulate real-time bin data

SCOPES = ['https://www.googleapis.com/auth/gmail.send']
TOKEN_FILE = 'token.json'
CREDENTIALS_FILE = 'credentials.json'

def get_gmail_service():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)



def create_message(sender, to, subject, body):
    message = MIMEMultipart()
    message['to'] = to
    # message['from'] = sender
    message['from'] = f"EnviroSense AI <{sender}>"
    message['subject'] = subject

    message.attach(MIMEText(body, 'plain'))

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
    return {'raw': raw_message}


def send_email(subject, body):
    try:
        service = get_gmail_service()
        collectors = get_collectors()
        if 'error' in collectors:
            print(collectors['error'])
            return

        for collector in collectors:
            email_address = collector['email']
            message = create_message('envirosenseai@gmail.com', email_address, subject, body)
            send_result = service.users().messages().send(userId='me', body=message).execute()
            print('Message Id: %s sent to %s' % (send_result['id'], collector))

    except HttpError as error:
        print(f'An error occurred: {error}')
        if hasattr(error, 'content'):
            print(f'Response content: {error.content.decode()}')


bin_levels = {
    "A4:CF:12:34:56:78": 0,
    "B8:27:EB:98:76:54": 0
}

@app.route('/realtime-data', methods=['GET'])
def get_realtime_data():
    global bin_levels

    for bin_no in bin_levels:
        if bin_levels[bin_no] == 100:
            send_email(
                subject="Bin Full Notification - Immediate Collection Required",
                body=f"Dear Trash Collection Team,\n\nThis is to inform you that Bin {bin_no} is now full and requires immediate collection.\n\nThank you for your prompt attention to this matter.\n\nBest regards,\nSupervisor"
            )
            bin_levels[bin_no] = random.randint(0, 10)  # Reset to a lower value
        else:
            bin_levels[bin_no] = min(bin_levels[bin_no] + random.randint(0, 10), 100)

    print(f"Checking bin {bin_no} with level {bin_levels[bin_no]}")

    mock_data = [
        {"bin_no": bin_no, "level": level, "timestamp": time.time()}
        for bin_no, level in bin_levels.items()
    ]

    return jsonify(mock_data)

@app.route('/collector', methods=['GET'])
def getCollectors():
    collectors = get_collectors()

    if isinstance(collectors, dict) and "error" in collectors:
        return jsonify(collectors), 500

    return jsonify(collectors)

@app.route('/collector/register', methods=['POST', 'GET'])
def register_collector():
    try:
        data = request.get_json()
        response, status_code = insert_collector(data)
        return jsonify(response), status_code

    except Exception as e:
        return jsonify({"message": "Internal server error"}), 500

@app.route('/collector/delete', methods=['DELETE'])
def delete_collector():
    collector_mail = request.args.get('email')
    if(collector_mail):
        result = deleteCollector(collector_mail)
        if result:
            return jsonify({"message": "Collector deleted successfully"}), 200
        else:
            return jsonify({"message": "Collector not found"}), 404
        return jsonify({"message": "Invalid request"}), 400

@app.route('/collector/update', methods=['PUT'])
def update_collector():
    previous_email = request.args.get('original_email')
    data = request.json

    if previous_email:
        collector = find_collector_by_email(previous_email)
        if collector:
            collector['name'] = data['name']
            collector['email'] = data['email']
            collector['phone_number'] = data['phone_number']
            updateCollector(previous_email, collector)
            return jsonify({"message": "Collector updated successfully"}), 200
        else:
            return jsonify({"error": "Collector not found"}), 404
    else:
        return jsonify({"error": "Invalid data"}), 400

@app.route('/meta/bin', methods=['GET'])
def get_bin_meta():
    binMeta, status_code = getBinMetadata()
    if not isinstance(binMeta, list):
        binMeta = []
    return jsonify(binMeta), status_code

if __name__ == "__main__":
    app.run(debug=True)

    # aneballo123@
    #  test.autho.124@gmail.com










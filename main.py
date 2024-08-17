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
import firebase_admin
import threading
from firebase_admin import credentials, db
import pandas as pd
import random
import time
import logging
import os
import base64
from ml_scripts.predictions import update_predictions, linear_regression_decision
from db_util import insert_user, get_user, update_user, update_password, save_profile_picture, \
    retrieve_bindata, fetch_bindata_byid, get_collectors, insert_collector, deleteCollector, find_collector_by_email, \
    updateCollector, getBinMetadata, find_bin_byid, update_bin_metadata, delete_bin_metadata, insert_bin_metadata, \
    get_user_by_email, insert_binfill_time
from data_auth import authenticate_user

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:3000"}})

app.config['JWT_SECRET_KEY'] = os.urandom(24)
jwt = JWTManager(app)

cred = credentials.Certificate("firebase-credentials.json")
firebase_admin.initialize_app(cred, {
    "databaseURL": "https://envirosense-5ef53-default-rtdb.asia-southeast1.firebasedatabase.app/"
})


def simulate_data():
    bins = ['B8:27:EB:98:76:54', 'CC:7B:5C:34:9F:1C']

    # bin_levels = {bin_no: 0 for bin_no in bins}
    # bin_levels = {bin_no: 15 for bin_no in bins}

    while True:
        for bin_no in bins:
            # bin_levels[bin_no] += random.randint(1, 10)
            bin_level_cm = random.randint(1, 15)
            bin_levels[bin_no] = bin_level_cm
            if bin_levels[bin_no] > 15:
                bin_levels[bin_no] = 15

            ref = db.reference(f'{bin_no}')
            ref.set({
                'Bin_Level': bin_levels[bin_no],
                'Timestamp': time.time()
            })

            print(f"bin level: Bin = {bin_no}, Fill Level = {bin_levels[bin_no]}")

        time.sleep(30)


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
        logger.debug("idinfo: %s", idinfo)

        email = idinfo.get('email')
        name = idinfo.get('name')
        picture = idinfo.get('picture')

        user_data = {
            'email': email,
            'username': email,
            'password': None,
            'phone': '',
            'file_path': picture
        }
        # Check if user already exists
        existing_user = get_user(email)
        if existing_user:
            if existing_user.get('profile_picture') != picture:
                save_profile_picture(email, picture)
            username = email
            access_token = create_access_token(identity=email)
            return jsonify(access_token=access_token, username=email), 200

        response, status_code = insert_user(user_data)
        save_profile_picture(email, picture)
        if status_code == 200:
            access_token = create_access_token(identity=email)
            return jsonify(access_token=access_token, username=email), 200
        else:
            return jsonify(response), status_code

    except ValueError as e:
        logger.error("Token verification failed: %s", str(e))
        return jsonify({"message": "Invalid token"}), 401


@app.route('/logout', methods=['POST'])
def logout():
    response = jsonify({"message": "Logged out successfully"})
    response.set_cookie('access_token', '', expires=0)  # Clear the cookie
    return response, 200





# get user (editProfile)
@app.route('/user', methods=['GET'])
@jwt_required()
def get_user_route():
    username = get_jwt_identity()

    if username:
        user_data = get_user(username)
        logger.debug('User data retrieved: %s', user_data)

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
            return

        for collector in collectors:
            email_address = collector['email']
            message = create_message('envirosenseai@gmail.com', email_address, subject, body)
            service.users().messages().send(userId='me', body=message).execute()

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
    try:
        ref = db.reference()

        data = ref.get()
        print("Data from DB:", data)
        result = []
        if data:
            for bin_no, record in data.items():
                fill_level = record.get('Bin_Level')
                print(f"Processing bin_no: {bin_no}, fill_level: {fill_level}")
                bin_level_percent = int((fill_level / 15) * 100)

                result.append({
                    "bin_no": bin_no,
                    "Bin_Level": bin_level_percent,
                    "Timestamp": time.time()
                })

                if fill_level >= 14:
                    # Send email notification
                    send_email(
                        subject="Bin Full Notification - Immediate Collection Required",
                        body=f"Dear Trash Collection Team,\n\nThis is to inform you that Bin {bin_no} is now full and requires immediate collection.\n\nThank you for your prompt attention to this matter.\n\nBest regards,\nSupervisor"
                    )

                    # insert_binfill_time(bin_no)

                    # Reset fill level to a lower value
                    # ref.child(bin_no).update({
                    #     'Bin_Level': random.randint(0, 1),
                    #     'Timestamp': time.time()
                    # })

        print("Data sent to frontend:", result)
        return jsonify(result)

    except Exception as e:
        print("Error occurred:", str(e))
        return jsonify({"error": "Server Error", "message": str(e)}), 500

bin_processed = {}
def get_bin_filltime() :
    try:
        ref = db.reference()
        data = ref.get()

        if data:
            for bin_no, record in data.items():
                bin_level = record.get('Bin_Level')
                print(f"Checking bin_no: {bin_no}, Bin_Level: {bin_level}")

                if bin_level >= 14:
                    if bin_no not in bin_processed or bin_processed[bin_no] is None:
                        insert_binfill_time(bin_no)
                        bin_processed[bin_no] = True
                        print(f"Bin {bin_no} processed and inserted.")
                    else:
                        print(f"Bin {bin_no} already processed.")
                else:
                    if bin_no in bin_processed:
                        if bin_processed[bin_no] is not None:
                            print(f"Bin {bin_no} level below 14, resetting tracking.")
                        bin_processed[bin_no] = None

    except Exception as e:
        print(f"An error occurred: {e}")

def periodic_bin_filltime_check():
    while True:
        get_bin_filltime()
        time.sleep(20)

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
    if (collector_mail):
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


@app.route('/meta/bin/update', methods=['PUT'])
def update_bin_meta():
    bin_no = request.args.get('bin_no')
    data = request.json
    if bin_no:
        bin_meta = find_bin_byid(bin_no)

        if bin_meta:
            bin_meta['bin_name'] = data['bin_name']
            bin_meta['location'] = data['location']

            update_bin_metadata(bin_no, bin_meta)
            return jsonify({"message": "Collector updated successfully"}), 200
        else:
            return jsonify({"error": "Collector not found"}), 404
    else:
        return jsonify({"error": "Invalid data"}), 400


@app.route('/meta/bin/delete', methods=['DELETE'])
def delete_bin_meta():
    bin_no = request.args.get('bin_no')
    if (bin_no):
        result = delete_bin_metadata(bin_no)
        if result:
            return jsonify({"message": "Collector deleted successfully"}), 200
        else:
            return jsonify({"message": "Collector not found"}), 404
        return jsonify({"message": "Invalid request"}), 400


@app.route('/meta/bin/add', methods=['POST'])
def add_bin_meta():
    try:
        data = request.get_json()
        response, status_code = insert_bin_metadata(data)
        return jsonify(response), status_code
    except Exception as e:
        return jsonify({"message": "Internal server error"}), 500


if __name__ == "__main__":
    data_thread = threading.Thread(target=simulate_data)
    data_thread.daemon = True  # Allows the thread to exit when the main program exits
    data_thread.start()

    periodic_bin_filltime_check()

    app.run(debug=True)
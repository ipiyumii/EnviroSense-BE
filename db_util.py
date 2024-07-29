import mysql.connector
import pandas as pd
from werkzeug.security import generate_password_hash
from mysql.connector import Error
from sqlalchemy import create_engine
from datetime import datetime, timedelta

def db_con():
    try:
        connection = mysql.connector.connect(
            user='root',
            password='root',
            host='localhost',
            port=3306,
            database='EnviroSenseAI_db'

        )
        if connection.is_connected():
            print("connected!")
            return connection

    except Error as e:
        print(f"Error: {e}")
        return None

def insert_bindata(data):
    connection = db_con()
    if not connection:
        return False

    try:
        cur = connection.cursor()
        for bin_id, timestamps in data.items():
            query = "SELECT BinName FROM bins WHERE BinID = %s"
            cur.execute(query, (bin_id,))
            bin_name = cur.fetchone()[0]

            for timestamp in timestamps:
                query = "INSERT INTO sensor_data (binID,DateTime, BinName) VALUES (%s, %s, %s)"
                cur.execute(query, (bin_id, timestamp, bin_name))

        connection.commit()

        return True

    except Exception as e:
        print(f"Error occurred: {e}")
        return False

    finally:
        if cur:
            cur.close()
        if connection and connection.is_connected():
            connection.close()

def retrieve_bindata():
    connection = db_con()
    if not connection:
        return None

    try:
        engine = create_engine('mysql+mysqlconnector://root:root@localhost:3306/EnviroSenseAI_db')

        query = "SELECT timestamp, bin_no FROM Bin_Data;"

        # query = f"""
        # SELECT * FROM Bin_Data
        # WHERE timestamp >= '{date_15_days_ago_str}'
        # """

        df = pd.read_sql(query, engine)
        return df
    except Exception as e:
        print(f"Error occurred: {e}")
        return None

    finally:
        connection.close()


def fetch_bin_name_mapping():
    connection = db_con()
    if not connection:
        return None

    try:
        query = "SELECT bin_no, bin_name FROM bins"

        cursor = connection.cursor()
        cursor.execute(query)

        bin_name_mapping = dict(cursor.fetchall())

        cursor.close()
        connection.close()

        return bin_name_mapping

    except Exception as e:
        print(f"Error occurred: {e}")
        return None

    finally:
        connection.close()

def get_user(username):
    connection = db_con()
    if not connection:
        print("Failed to connect to the database")
        return False

    try:
        cur = connection.cursor(dictionary=True)
        query = "SELECT a.email,a.name,a.username,a.password,a.phone, p.file_path FROM Admin a LEFT JOIN profile_pictures p ON a.username = p.username WHERE a.username = %s;"
        cur.execute(query, (username,))
        userData = cur.fetchone()

        if userData:
            print("User data retrieved:", userData)
            return userData
        else:
            print("User does not exist")
            return False

    except Exception as e:
        print(f"Error: {e}")
        return False

    finally:
        if cur:
            cur.close()
        if connection and connection.is_connected():
            connection.close()
            print("mysql connection is closed in getUser")

def insert_user(data):
    # connection = None
    # cur = None
    connection = db_con()
    if not connection:
        return {"message": "db connection failed"}, 500

    try:
        with connection.cursor(dictionary=True) as cur:
            email = data.get('email')
            username = data.get('username')

            query = "SELECT * FROM Admin WHERE email = %s"
            cur.execute(query, (email,))
            user = cur.fetchone()
            cur.fetchall()

            if user:
                print("User already exists")
                return {"message": "This email is already used!"}, 400

            else:
                query = "SELECT * FROM Admin WHERE username = %s"
                cur.execute(query, (username,))
                user = cur.fetchone()
                cur.fetchall()

                if user:
                    print("username has already taken!")
                    return {"message": "username has already taken!"}, 400
                else:
                    phone = data.get('phone')
                    # username = data.get('username')
                    password = data.get('password')
                    password_hash = generate_password_hash(password) if password else None

                    query = "INSERT INTO Admin (email,phone, username,password) VALUES (%s, %s, %s, %s)"
                    cur.execute(query, (email, phone, username, password_hash))

                    connection.commit()
                    print("successfully inserted into Admin table")
                    return {"message": "User registered"}, 200

    except Exception as e:
        print(f"Error: {e}")
        return {"message": "error occurred while inserting user"}, 500

    finally:
        if cur:
            cur.close()
        if connection and connection.is_connected():
            connection.close()
            print("mysql connection is closed in insertUser")

def update_user(data, current_username):
    # connection = None
    connection = db_con()
    if not connection:
        return {"error": "db connection failed"}, 500

    try:
        with connection.cursor(dictionary=True) as cur:
            new_username = data.get('username')
            email = data.get('email')
            phone = data.get('phone')
            name = data.get('name')

            #check if the new username is available
            if new_username != current_username:
                query = "SELECT * FROM Admin WHERE username = %s"
                cur.execute(query, (new_username,))
                user = cur.fetchone()
                # cur.fetchall()

                if user:
                    return {"message": "username has already taken!"}, 400

            query = "UPDATE Admin SET username = %s , email = %s, phone = %s, name = %s WHERE username = %s"
            cur.execute(query, (new_username, email, phone, name, current_username))
            connection.commit()
            return {"message": "user updated successfully"}, 200

    except Error as e:
        print(f"Error: {e}")
        return {"error": "error occurred while updating the user"}, 500

    finally:
        if connection.is_connected():
            connection.close()
            print("mysql connection is closed")

def update_password(data):
    connection = db_con()
    if not connection:
        return {"error": "db connection failed"}, 500

    try:
        with connection.cursor(dictionary=True) as cur:
            username = data.get('username')
            password = data.get('password')
            new_password = data.get('newPassword')
            confirm_password = data.get('confirmPassword')

            password_hash = generate_password_hash(new_password)

            query = "UPDATE Admin SET password = %s  WHERE username = %s"
            cur.execute(query, (password_hash, username))
            connection.commit()
            return {"message": "User updated successfully"}, 200

    except Error as e:
        print(f"Error: {e}")
        return {"error": "error occurred while updating the user"}, 500

    finally:
        if cur:
            cur.close()
        if connection and connection.is_connected():
            connection.close()
            print("sql connection is closed in getUser")

def save_profile_picture(username, file_url):
    connection = db_con()
    if not connection:
        return {"error": "Database connection failed"}, 500

    try:
        with connection.cursor(dictionary=True) as cur:

            query = "SELECT file_path FROM profile_pictures WHERE username = %s"
            cur.execute(query, (username,))
            user = cur.fetchone()

            if user:
                query = "UPDATE profile_pictures SET file_path = %s WHERE username = %s"
                cur.execute(query, (file_url, username))
                connection.commit()
                return {"message": "pp updated successfully"}, 200

            else:
                query = "INSERT INTO profile_pictures (username, file_path) VALUES (%s, %s)"
                cur.execute(query, (username, file_url))
                connection.commit()
                return {"message": "pp added successfully"}, 200

    except Error as e:
        print(f"Error: {e}")
        return {"error": "error occurred while updating the user"}, 500

    finally:
        if connection.is_connected():
            connection.close()
            print("sql connection is closed")


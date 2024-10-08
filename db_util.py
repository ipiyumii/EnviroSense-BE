from datetime import datetime

import mysql.connector
import pandas as pd
from werkzeug.security import generate_password_hash
from mysql.connector import Error
from sqlalchemy import create_engine

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
            return connection

    except Error as e:
        print(f"Error: {e}")
        return None

def insert_bindata(data):
    connection = db_con()
    if not connection:
        return [], 500

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
        return [], 500
    try:
        engine = create_engine('mysql+mysqlconnector://root:root@localhost:3306/EnviroSenseAI_db')

        query = "SELECT timestamp, bin_no FROM Bin_Data;"

        df = pd.read_sql(query, engine)
        return df

    except Exception as e:
        print(f"Error occurred: {e}")
        return None
    finally:
        connection.close()

def fetch_bindata_byid(bin_no, start_date, end_date):
    connection = db_con()
    if not connection:
        return [], 500

    try:
        cur = connection.cursor()
        # query = "SELECT timestamp, bin_no FROM Bin_Data WHERE bin_no = %s"
        query = """
                   SELECT timestamp, bin_no
                   FROM Bin_Data
                   WHERE bin_no = %s
                     AND timestamp >= %s
                     AND timestamp <= %s
               """

        start_date_str = start_date.strftime('%Y-%m-%d %H:%M:%S')
        end_date_str = end_date.strftime('%Y-%m-%d %H:%M:%S')

        cur.execute(query, (bin_no, start_date_str, end_date_str))
        result = cur.fetchall()

        df = pd.DataFrame(result, columns=['timestamp', 'bin_no'])
        return df

    except Exception as e:
        print(f"Error occurred: {e}")
        return None
    finally:
        cur.close()
        connection.close()

def fetch_bin_name_mapping():
    connection = db_con()
    if not connection:
        return [], 500

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
        return [], 500

    try:
        cur = connection.cursor(dictionary=True)
        # query = "SELECT a.email,a.name,a.username,a.password,a.phone, p.file_path FROM Admin a LEFT JOIN profile_pictures p ON a.username = p.username WHERE a.username = %s;"
        query = """
                    SELECT 
                        a.email, a.name, a.username, a.password, a.phone, 
                        COALESCE(p.file_path, '') AS file_path
                    FROM Admin a 
                    LEFT JOIN profile_pictures p ON a.username = p.username 
                    WHERE a.username = %s;
                """
        cur.execute(query, (username,))
        userData = cur.fetchone()

        if userData:
            return userData
        else:
            return False

    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        if cur:
            cur.close()
        if connection and connection.is_connected():
            connection.close()

def get_user_by_email(email):
    connection = db_con()
    if not connection:
        return [], 500

    try:
        cur = connection.cursor(dictionary=True)
        query = """
                    SELECT a.email, a.name, a.username, a.password, a.phone, p.file_path 
                    FROM Admin a 
                    LEFT JOIN profile_pictures p ON a.email = p.username
                    WHERE a.email = %s;
                """
        cur.execute(query, (email,))
        userData = cur.fetchone()

        if userData:
            return userData
        else:
            return False

    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        if cur:
            cur.close()
        if connection and connection.is_connected():
            connection.close()

def insert_user(data):
    connection = db_con()
    if not connection:
        return [], 500

    try:
        with connection.cursor(dictionary=True) as cur:
            email = data.get('email')
            username = data.get('username')

            query = "SELECT * FROM Admin WHERE email = %s"
            cur.execute(query, (email,))
            user = cur.fetchone()
            cur.fetchall()

            if user:
                return {"message": "This email is already used!"}, 400

            else:
                query = "SELECT * FROM Admin WHERE username = %s"
                cur.execute(query, (username,))
                user = cur.fetchone()
                cur.fetchall()

                if user:
                    return {"message": "username has already taken!"}, 400
                else:
                    phone = data.get('phone')
                    # username = data.get('username')
                    password = data.get('password')
                    password_hash = generate_password_hash(password) if password else None

                    query = "INSERT INTO Admin (email,phone, username,password) VALUES (%s, %s, %s, %s)"
                    cur.execute(query, (email, phone, username, password_hash))

                    connection.commit()
                    return {"message": "User registered"}, 200

    except Exception as e:
        print(f"Error: {e}")
        return {"message": "error occurred while inserting user"}, 500

    finally:
        if cur:
            cur.close()
        if connection and connection.is_connected():
            connection.close()

def update_user(data, current_username):
    connection = db_con()
    if not connection:
        return [], 500

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

def update_password(data):
    connection = db_con()
    if not connection:
        return [], 500

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

def save_profile_picture(username, file_url):
    connection = db_con()
    if not connection:
        return [], 500

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

def get_collectors():
    connection = db_con()
    if not connection:
        return [], 500
    try:
        with connection.cursor(dictionary=True) as cur:
            query = "SELECT name,phone_number, email FROM collectors"
            cur.execute(query)
            recipients = cur.fetchall()
            connection.commit()
            return recipients

    except Error as e:
        print(f"Error: {e}")
        return {"error": "error occurred while updating the user"}, 500
    finally:
        if connection.is_connected():
            connection.close()

def insert_collector(data):
    connection = db_con()
    if not connection:
        return [], 500
    try:
        with connection.cursor(dictionary=True) as cur:
            email = data.get('email')
            name = data.get('name')
            phone_number = data.get('phone_number')

            query = "INSERT INTO `collectors`(`name`, `phone_number`, `email`) VALUES(%s,%s,%s)"
            cur.execute(query, (name, phone_number, email))

        connection.commit()
        return {"message": "User registered"}, 200

    except Exception as e:
        print(f"Error: {e}")
        return {"message": "error occurred while inserting user"}, 500

    finally:
        if cur:
            cur.close()
        if connection and connection.is_connected():
            connection.close()


def deleteCollector(email):
    connection = db_con()
    if not connection:
        return [], 500
    try:
        with connection.cursor(dictionary=True) as cur:
            query = 'DELETE FROM `collectors` WHERE email = %s'
            cur.execute(query, email)

        connection.commit()
        return {"message": "User registered"}, 200

    except Exception as e:
        print(f"Error: {e}")
        return {"message": "error occurred while inserting user"}, 500
    finally:
        if cur:
            cur.close()
        if connection and connection.is_connected():
            connection.close()


def updateCollector(original_email, data):
    connection = db_con()
    if not connection:
        return [], 500
    try:
        with connection.cursor(dictionary=True) as cur:
            query = 'UPDATE collectors SET name = %s, phone_number = %s, email = %s WHERE email = %s'
            cur.execute(query, (data['name'], data['phone_number'], data['email'], original_email))

            connection.commit()
            return {"message": "User registered"}, 200

    except Exception as e:
        print(f"Error: {e}")
        return {"message": "error occurred while inserting user"}, 500
    finally:
        if connection and connection.is_connected():
            connection.close()

def find_collector_by_email(email):
    connection = db_con()
    if not connection:
        return [], 500
    try:
        with connection.cursor(dictionary=True) as cur:
            query = 'SELECT `name`, `phone_number`, `email` FROM collectors WHERE email = %s'
            cur.execute(query, (email,))

            result = cur.fetchone()
            return result

    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        if connection and connection.is_connected():
            connection.close()

def getBinMetadata():
    connection = db_con()
    if not connection:
        return [], 500
    try:
        with connection.cursor(dictionary=True) as cur:
            query = "SELECT `bin_no`, `bin_name`, `location` FROM `bins`"
            cur.execute(query)
            bin_meta = cur.fetchall()
            return bin_meta, 200

    except Error as e:
        print(f"Error: {e}")
        return [], 500
    finally:
        if connection.is_connected():
            connection.close()

def find_bin_byid(bin_no):
    connection = db_con()
    if not connection:
        return [], 500
    try:
        with connection.cursor(dictionary=True) as cur:
            query = 'SELECT * FROM `bins` WHERE `bin_no` = %s'
            cur.execute(query, (bin_no,))

            result = cur.fetchone()
            return result

    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        if connection and connection.is_connected():
            connection.close()

def update_bin_metadata(bin_no, bin_meta):
    connection = db_con()
    if not connection:
        return [], 500

    try:
        with connection.cursor(dictionary=True) as cur:
            query = 'UPDATE `bins` SET `bin_name`= %s,`location`=%s WHERE bin_no = %s'
            cur.execute(query, (bin_meta['bin_name'], bin_meta['location'], bin_no))

            connection.commit()
            return {"message": "User registered"}, 200

    except Exception as e:
        print(f"Error: {e}")
        return {"message": "error occurred while inserting user"}, 500
    finally:
        if connection and connection.is_connected():
            connection.close()


def delete_bin_metadata(bin_no):
    connection = db_con()
    if not connection:
        return [], 500
    try:
        with connection.cursor(dictionary=True) as cur:
            query = 'DELETE FROM `bins` WHERE bin_no = %s'
            cur.execute(query, (bin_no,))

        connection.commit()
        return {"message": "Collector deleted successfully"}, 200

    except Exception as e:
        print(f"Error: {e}")
        return {"message": "Error occurred while deleting collector"}, 500
    finally:
        if cur:
            cur.close()
        if connection and connection.is_connected():
            connection.close()

def insert_bin_metadata(data):
    connection = db_con()
    if not connection:
        return [], 500
    try:
        with connection.cursor(dictionary=True) as cur:
            bin_no = data.get('bin_no')
            bin_name = data.get('bin_name')
            location = data.get('location')

            query = "INSERT INTO `bins`(`bin_no`, `bin_name`, `location`) VALUES (%s,%s,%s)"
            cur.execute(query, (bin_no, bin_name, location))

        connection.commit()
        return {"message": "User registered"}, 200

    except Exception as e:
        print(f"Error: {e}")
        return {"message": "error occurred while inserting user"}, 500
    finally:
        if cur:
            cur.close()
        if connection and connection.is_connected():
            connection.close()

def insert_binfill_time(bin_no):
    connection = db_con()
    if not connection:
        return [], 500

    try:
        with connection.cursor(dictionary=True) as cur:
            current_time = datetime.now()

            sql_query = "INSERT INTO bin_fill_data (bin_no, timestamp) VALUES (%s, %s)"
            cur.execute(sql_query, (bin_no, current_time))
            connection.commit()
            print(f"Inserted bin_no: {bin_no} with current timestamp into database.")

    except Exception as e:
        print(f"Error inserting data: {e}")
    finally:
        connection.close()
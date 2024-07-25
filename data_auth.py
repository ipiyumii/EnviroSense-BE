from db_util import get_user
from werkzeug.security import generate_password_hash, check_password_hash


def authenticate_user(data):
    username = data.get('username')
    password = data.get('password')

    # password_hash = generate_password_hash(data['password'])

    user = get_user(username)
    if user:
        hashed_password = user.get('password')
        if check_password_hash(hashed_password, password):
            return {"message": "Password is correct"}, 200
        else:
            return {"message": "Password is incorrect"}, 401
    else:
        return {"message": "User not found"}, 404

        # if user.get('password') == password_hash:
        #     print("passowrd is correct")
        #     return {"message": "Password is correct"}, 200
        # else:
        #     print("passowrd is incorrect")
        #     return {"message": "Password is incorrect"}, 200












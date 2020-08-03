# Create a system for user management for a video surveillance system.
# The system should have three level if hierarchy as follows:
#
# 1)Head office admin
# 2)Branch admin
# 3)Supervisor
#
# Working:
#
# The head office admin can view details of branch admin and supervisor as well as camera details.
#  details as well as camera details.
# The supervisor can only view camera details.The branch admin can only view supervisor
# Only head  office admin and branch office admin can modify, delete and add camera in database.
# Supervisor will get unauthenticated error in return.if he tries to modify / add camera. Passjwt(json web
# token) token in header to verify head office admin / branch admin / supervisor.
# Required apis:
# Api to add branch admin, Api to add supervisor ,Api to add, modify, delete, view camera details
# Note:
# Create static Head office admin with username and password as ‘admin’
# Create tables and columns according to your understanding of the problem statement
# Use mysql for backend database
# Use pyjwt library for differentiate between Head office, branch office and supervisor and also for authentication
# Flowchart of working is mandatory Error handling for each api is mandatory
# Swagger documentation is optional
# Production folder structure is optional
# The code should be well documented
# All api should be tested before submission

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
db = SQLAlchemy()

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://dbda:dbda@localhost/DIYCAM'
app.config['SECRET_KEY'] = "random string"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# when any request will be made first it will create all the tables and
# it will insert username and password as 'admin' and position as 'head_office_admin'.
@app.before_first_request
def create_tables():
    db.create_all()
    User.add_admin("admin", "admin", "head_office_admin")


class User(db.Model):
    """this class will create table with name 'head_office_admin' """
    __tablename__ = "user"

    # creating columns id, username, password, email_id
    username = db.Column(db.String(30), primary_key=True, unique=True)
    password = db.Column(db.String(30), nullable=False)
    position = db.Column(db.String(30), nullable=False)

    def __init__(self, username, password, position):
        self.username = username
        self.password = password
        self.position = position

    # static method to insert username and password as 'admin'
    @staticmethod
    def add_admin(username, password, position):

        # find if the admin already exist in table
        user = User.query.filter_by(username=username).first()

        # if admin not found then it will create user by username and password as 'admin' and
        # position as 'head_office_admin'
        if not user:
            admin = User(username, password, position)

            # add admin to user table
            db.session.add(admin)

            # make changes to table
            db.session.commit()
        # if user already exist then it will not make any changes
        else:
            pass


class Camera(db.Model):
    """this class will create table with name 'camera' which will contain details of cameras"""
    __tablename__ = "camera"

    # creating columns id , camera_id, location, function
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    camera_id = db.Column(db.String(20), unique=True)
    location = db.Column(db.String(20))
    function = db.Column(db.String(20))

    # constructor of class user
    def __init__(self, camera_id, location, function):
        self.camera_id = camera_id
        self.location = location
        self.function = function


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # checking "x-access-token is there in header to which we will be feeding token"
        if 'x-access-token' in request.headers:
            # requesting token in header

            token = request.headers['x-access-token']
            print("token", token)

        # if token not passed
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # decode the token and find the current user
            data = jwt.decode(token, app.config['SECRET_KEY'])
            print("data:",data)
            current_user = User.query.filter_by(username=data['username']).first()
        except Exception as e:
            print(e)
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/", methods=["GET"])
def home():
    return jsonify({'message': 'successfully created tables!'}), 200


@app.route('/login', methods=["GET"])
def login():
    """this function is to login the user and create the web token for further request"""
    try:
        # request fot authorization
        auth = request.authorization

        # if all data is available
        if auth and auth.username and auth.password:

            # if the authentication username is available is the user table then only he can login
            user = User.query.filter_by(username=auth.username).first()

            # if user is available
            if user:
                # if password is matched
                if user.password == auth.password:
                    # create token with the help of username, secret_key  which will have expiry of 30 mins
                    token = jwt.encode(
                        {'username': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                        app.config['SECRET_KEY'])

                    return jsonify({'token': token.decode('UTF-8')})
                else:
                    # if password not matched
                    return make_response('password not matched', 401)
            else:
                # if user not found
                return make_response('no user found', 401)
        else:
            # if all data is not sent
            return make_response('Empty parameters', 401)
    except Exception as e:
        print(e)
        return make_response('Bad Request', 400)


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    """ 1)this function will list all users to head_office_admin.
        2) it will list only supervisors if the logged in user is 'branch_office_admin'
        3) it will return Unauthenticated! if logged in user is 'supervisor'
    """
    # if the logged in user is "head_office_admin"
    if current_user.position == "head_office_admin":

        # retrieve all users for user table
        # users = User.query.filter_by(position != "head_office_admin").all()
        users = User.query.all()
        # empty list for the add all users and returning the list
        output = []

        for user in users:
            user_data = {'username': user.username, 'position': user.position}
            output.append(user_data)

        return jsonify({'users': output})

    # if the logged in user is "branch_office_admin"
    elif current_user.position == "branch_office_admin":

        # retrieve only supervisors data from the table
        users = User.query.filter_by(position="supervisor").all()
        output = []

        for user in users:
            user_data = {'username': user.username, 'position': user.position}
            output.append(user_data)

        return jsonify({'users': output})

    # if the logged in user is "supervisor" return 'Unauthenticated!'
    elif current_user.position == "supervisor":
        return jsonify({'message': 'Unauthenticated! Please contact head office admin to get privileges'}), 401

    # if the user had position other than "head_office_admin", "branch_office_admin", "supervisor"
    else:
        return jsonify({'message': 'Unauthenticated!'}), 401


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    """this function creates new user if user is head_office_admin
    { "username": "admin", "password": "admin", "position": "head_office_admin" }
                     or
    { "username": "branch", "password": "branch", "position": "branch_office_admin" }
                     or
    { "username": "sup", "password": "sup", "position": "supervisor" }
    """
    # if the logged in user is "head_office_admin"
    if current_user.position == "head_office_admin":

        # request data from user
        username = request.json['username']
        password = request.json['password']
        position = request.json['position']

        # if all the data is available
        if username and password and position:
            user = User.query.filter_by(username=username).all()
            if not user:
                new_user = User(username, password, position)

                # add new user
                db.session.add(new_user)
                db.session.commit()
                return jsonify({'message': 'New user created!'}), 200
            else:
                return jsonify({'message': 'user already exist!! use different username'}), 422

        else:
            # if not received any of the required data then it will return 'Empty parameters'
            return jsonify({'message': 'Empty parameters'}), 422
    else:
        # if the user is other than head_office-admin it will return 'Unauthenticated!'
        return jsonify({'message': 'Unauthenticated!'}), 401


@app.route('/camera', methods=['GET'])
@token_required
def get_camera(current_user):
    """ 1)this function will list all cameras details to 'head_office_admin' and 'branch_office_admin' and 'supervisor'
        2) it will return Unauthenticated! if logged in user is not from user table
    """
    # if the logged in user is "head_office_admin" or "branch_office_admin" or "supervisor"
    if current_user.position == "head_office_admin" or current_user.position =="branch_office_admin" or \
            current_user.position =="supervisor":

        # retrieve all users for user table
        cameras = Camera.query.all()

        # empty list for the add all cameras and returning the list
        output = []

        for camera in cameras:
            camera_data = {'camera_id': camera.camera_id, 'location': camera.location, 'function': camera.function}
            output.append(camera_data)

        return jsonify({'cameras': output}), 200
    # if the user had position other than "head_office_admin", "branch_office_admin", "supervisor"
    else:
        return jsonify({'message': 'Unauthenticated! Please contact head office admin to get privileges'}), 401


@app.route('/camera', methods=['POST'])
@token_required
def add_camera(current_user):
    """this function adds camera object in database
                    {"camera_id": "camera1", "location": "indoor", "function": "container" }
                                        or
                    { "camera_id": "camera2", "location": "outdoor", "function": "truck" }
    """
    # if user is "head_office_admin" or "branch_office_admin" then only he can add camera in table
    if current_user.position == "head_office_admin" or current_user.position == "branch_office_admin":
        # request user for data
        camera_id = request.json['camera_id']
        location = request.json['location']
        function = request.json['function']

        # if all data availableY

        if camera_id and location and function:
            camera = Camera.query.filter_by(camera_id=camera_id).all()
            if not camera:
                camera = Camera(camera_id, location, function)

                # add camera object to table
                db.session.add(camera)

                # make changes to table
                db.session.commit()
                return jsonify({'message': 'camera added!'}), 200
            else:
                return jsonify({'message': 'camera object exist with same name!'}), 403

        else:
            # if all required data is not available
            return jsonify({'message': 'Empty parameters'}), 422
    else:
        # if the user is other than "head_office_admin" or "branch_office_admin"
        return jsonify({'message': 'Unauthenticated!'}), 401


@app.route('/camera', methods=['PUT'])
@token_required
def modify_camera(current_user):
    """this function allows 'head_office_admin' and 'branch_office_admin' to modify camera details
            {"camera_id": "1", "location": "outdoor", "function": "truck" }
    """

    if current_user.position == "head_office_admin" or current_user.position == "branch_office_admin":
        # request user for data
        camera_id = request.json['camera_id']
        location = request.json['location']
        function = request.json['function']

        # finding if the camera_id is available in the table
        camera = Camera.query.filter_by(camera_id=camera_id).first()
        # if camera object is found, (location and function) data is received
        if camera and location and function:

            # modify details
            camera.location = location
            camera.function = function

            # make changes to table
            db.session.commit()
            return jsonify({'message': 'camera details modified!'}), 200
        else:
            # if no camera found with given camera_id or required data is not received
            return jsonify({'message': 'camera not found / Empty parameters'}), 422
    else:
        # if user is other than "head_office_admin" and "branch_office_admin" returns 'Unauthenticated!'
        return jsonify({'message': 'Unauthenticated!'}), 401


@app.route('/camera', methods=['DELETE'])
@token_required
def delete_camera(current_user):
    """this function delete camera object from camera table if user is 'head_office_admin' or 'branch_office_admin'
        { "camera_id": "camera2"}
    """
    if current_user.position == "head_office_admin" or current_user.position == "branch_office_admin":
        # request user for data
        camera_id = request.json['camera_id']

        # finding if the camera_id is available in the table
        camera = Camera.query.filter_by(camera_id=camera_id).first()

        # if camera is available in table
        if camera:
            # delete particular camera object
            db.session.delete(camera)

            # make changes to table
            db.session.commit()
            return jsonify({'message': 'camera deleted!'}), 200
        else:
            # if no camera found with given camera_id or required data is not received
            return jsonify({'message': 'camera not found / Empty parameters'}), 422
    else:
        # if user is other than "head_office_admin" and "branch_office_admin" returns 'Unauthenticated!'
        return jsonify({'message': 'Unauthenticated!'}), 401


if __name__ == '__main__':
    db.init_app(app)
    app.run(debug=True)
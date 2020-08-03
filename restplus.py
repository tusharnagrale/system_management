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
from flask_restplus import Api, Resource, fields
import jwt
import datetime
from functools import wraps


app = Flask(__name__)
db = SQLAlchemy()

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://dbda:dbda@localhost/DIYCAM'
app.config['SECRET_KEY'] = "random string"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# system_management = "system_management"
# name_space = Namespace(system_management)
authorizations = {
    'apikey' : {
        'type' : 'apiKey',
        'in' : 'header',
        'name' : 'x-access-token'
    }
}

api = Api(app, authorizations= authorizations, version='1.0', title='System Management')

# when any request will be made first it will create all the tables and
# it will insert username and password as 'admin' and position as 'head_office_admin'.
# @app.before_first_request
# def create_tables():
#     db.create_all()
#     Users.add_admin("admin", "admin", "head_office_admin")


class Users(db.Model):
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

    def serialize(self):
        return {
            "username": self.username,
            "position": self.position,
        }

    # static method to insert username and password as 'admin'
    @staticmethod
    def add_admin(username, password, position):

        # find if the admin already exist in table
        user = Users.query.filter_by(username=username).first()

        # if admin not found then it will create user by username and password as 'admin' and
        # position as 'head_office_admin'
        if not user:
            admin = Users(username, password, position)

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

# all the serializers to take input from swagger
login_post_in = api.model('Login_Post_In', {'username' : fields.String, 'password' : fields.String})

user_post_in = api.model('User_Post_In', {'username' : fields.String, 'password' : fields.String, 'position' : fields.String})

camera_post_in = api.model('Camera_Post_In', {'camera_id': fields.String,'location' : fields.String, 'function' : fields.String('function')})

camera_put_in = api.model('Camera_Put_In', {'camera_id': fields.String,'location' : fields.String, 'function' : fields.String})

camera_delete_in = api.model('Camera_Delete_In', {'camera_id': fields.String})


login_get_out = api.model('Login_Get_Out', {'token' : fields.String})

user_getmultiple_out = api.model('User_Get_Out', {'message' : fields.List(fields.Nested(login_post_in))})
#)
camera_get_out = api.model('Camera_Post_In', {'camera_id': fields.String, 'location' : fields.String, 'function' : fields.String})

def token_required(f):
    @wraps(f)
    def decorated(self,*args, **kwargs):
        print('inside the token required')
        token = None

        # checking "x-access-token is there in header to which we will be feeding token"
        if 'x-access-token' in request.headers:
            # requesting token in header
            token = request.headers['x-access-token']
            print('got the token',token)

        # if token not passed
        if not token:
            return {'message': 'Token is missing!'}, 401

        try:
            # decode the token and find the current user
            data = jwt.decode(token, app.config['SECRET_KEY'])
            print("data",data)
            current_user = Users.query.filter_by(username=data['username']).first()
            print("current user",current_user)
        except Exception as e:
            print(e)
            return {'message': 'Token is invalid!'}, 401

        return f(self, current_user, *args, **kwargs)

    return decorated


@api.route('/login')
class Login(Resource):

    @api.marshal_with(login_get_out)
    @api.expect(login_post_in)
    def post(self):
        """this function is to login the user and create the web token for further request"""
        try:
            # request fot authorization
            data = api.payload
            username = data['username']
            password = data['password']


            # if all data is available
            if data and username and password:

                # if the authentication username is available is the user table then only he can login
                user = Users.query.filter_by(username=username).first()

                # if user is available
                if user:
                    # if password is matched
                    if user.password == password:
                        # create token with the help of username, secret_key  which will have expiry of 30 mins
                        token = jwt.encode(
                            {'username': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                            app.config['SECRET_KEY'])

                        return {'token': token.decode('UTF-8')}, 200
                    else:
                        # if password not matched
                        return {'message': 'password not matched'}, 401
                else:
                    # if user not found
                    return {"message": "no user found"},401
            else:
                # if all data is not sent
                return {"message": "Empty parameters"}, 401
        except Exception as e:
            print(e)
            return 'Bad Request', 400



@api.route('/user')
class User(Resource):

    @api.doc(security='apikey')
    @token_required
    @api.marshal_with(user_getmultiple_out)
    def get(self,current_user):
        """
        this function will list the user on following conditions
        1)this function will list all users to head_office_admin.
        2) it will list only supervisors if the logged in user is 'branch_office_admin'.
        3) it will return Unauthenticated! if logged in user is 'supervisor'
        """
        # if the logged in user is "head_office_admin"
        try:
            if current_user.position == "head_office_admin":

                # retrieve all users for user table
                # users = Users.query.filter_by(position != "head_office_admin").all()
                users = Users.query.all()
                print("found user",users)
                # empty list for the add all users and returning the list
                output = []

                for user in users:
                    # print("user.username",user.username)
                    # print("user.position",user.position)
                    # user_data = {'username': user.username, 'position': user.position}
                    # output.append(user_data)
                    output.append(user.serialize())
                print("list",output)
                return jsonify({'users': output}), 200

            # if the logged in user is "branch_office_admin"
            elif current_user.position == "branch_office_admin":

                # retrieve only supervisors data from the table
                users = Users.query.filter_by(position="supervisor").all()
                output = []

                for user in users:
                    # output.append(user.serialize())
                    user_data = {'username': user.username, 'position': user.position}
                    output.append(user_data)

                return {'users': output}, 200

            # if the logged in user is "supervisor" return 'Unauthenticated!'
            elif current_user.position == "supervisor":
                return jsonify({'message': 'Unauthenticated! Please contact head office admin to get privileges'}), 401

            # if the user had position other than "head_office_admin", "branch_office_admin", "supervisor"
            else:
                return {"message": "Unauthenticated!"}, 401
        except Exception as e:
            print(e)

    @api.doc(security='apikey')
    @token_required
    @api.expect(user_post_in)
    def post(self, current_user):
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
                user = Users.query.filter_by(username=username).all()
                if not user:
                    new_user = Users(username, password, position)

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


@api.route('/camera')
class Camera(Resource):

    @api.doc(security='apikey')
    @token_required
    @api.marshal_with(camera_get_out)
    def get(self, current_user):
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
                # camera_data = {'camera_id': camera.camera_id, 'location': camera.location, 'function': camera.function}
                # output.append(camera_data)
                output.append(camera.serialize())

            return jsonify({'cameras': output}), 200
        # if the user had position other than "head_office_admin", "branch_office_admin", "supervisor"
        else:
            return jsonify({'message': 'Unauthenticated! Please contact head office admin to get privileges'}), 401

    @api.doc(security='apikey')
    @token_required
    @api.expect(camera_post_in)
    def post(self,current_user):
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

    @api.doc(security='apikey')
    @token_required
    @api.expect(camera_put_in)
    def put(self, current_user):
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
                return jsonify({'message': 'camera modified'})

    @api.doc(security='apikey')
    @token_required
    @api.expect(camera_delete_in)
    def delete(self,current_user):
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

# name_space.add_resource('Login',"/login")
# name_space.add_resource('Camera',"/camera")
# name_space.add_resource('User',"/user")

if __name__ == '__main__':
    db.init_app(app)
    with app.app_context():
        db.create_all()
        Users.add_admin("admin", "admin", "head_office_admin")
    app.run(debug=True)

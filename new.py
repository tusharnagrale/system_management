from flask import Flask
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)

db = SQLAlchemy()

app.config['SQLALCHEMY_DATABASE_URI']='mysql://dbda:dbda@localhost/classwork'
app.config['SECRET_KEY']= 'random string'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= False


class User(db.Model):
    __tablename__ = 'user'
    username = db.Column("username",db.String(30),primary_key = True)
    password = db.Column("password",db.String(40))
    position = db.Column("position",db.String(20))

    def __init__(self, username, password, position):
        self.username = username
        self.password = password
        self.position = position

    @staticmethod
    def add_admin():
        username = 'admin'
        password = 'admin'
        position = 'head_office_head'
        user = User.query.filter_by(username=username).first()

        if not user:
            admin = User(username, password , position)
            db.session.add(admin)
            db.session.commit()
            return {'message': 'success'}, 200
        else:
            pass

class Camera(db.Model):
    __tablename__ = 'camera'
    id = db.Column("id", db.Integer, autoincrement = True)
    camera_id = db.Column("camera_id", db.String(30), primary_key=True)
    location = db.Column("location", db.String(40))
    function = db.Column("function", db.String(20))

    def __init__(self, camera_id, location, function):
        self.camera_id = camera_id
        self.location = location
        self.function = function


@app.before_first_request
def create():
    db.create_all()
    User.add_admin()

if __name__ == '__main__':
    db.init_app(app)
    app.run(debug=True)
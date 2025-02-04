from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey

db = SQLAlchemy()

class Business_user(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    nif = db.Column(db.Integer, nullable=False)
    address = db.Column(db.String(150), nullable=False)
    payment_method = db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return '<Business_user %r>' % self.business_name

    def serialize(self):
        return {
            "id": self.id,
            "business_name": self.business_name,
            "email": self.email,
            "nif": self.nif,
            "address": self.address,
            "payment_method": self.payment_method
        }

class Offers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trip_id = db.Column(db.Integer, ForeignKey('trip.id'), nullable=False)
    business_id = db.Column(db.Integer, ForeignKey('business_user.id'), nullable=False)
    normal_user_price = db.Column(db.Integer, nullable=False)
    medium_user_price = db.Column(db.Integer, nullable=False)
    high_user_price = db.Column(db.Integer, nullable=False)
    premium_user_price = db.Column(db.Integer, nullable=False)
    trip_id = db.Column(db.Integer, db.ForeignKey('trip.id'), nullable=False)


    def __repr__(self):
        return '<Offers %r>' % self.id

    def serialize(self):
        return {
            "id": self.id,
            "trip_id": self.trip_id,
            "business_id": self.business_id,
            "normal_user_price": self.normal_user_price,
            "medium_user_price": self.medium_user_price,
            "high_user_price": self.high_user_price,
            "premium_user_price": self.premium_user_price
        }

class Trip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country = db.Column(db.String(40), nullable=False)
    city = db.Column(db.String(40), nullable=False)
    activities = db.Column(db.String(100), nullable=False)
    offers = db.relationship('Offers', backref='trip', lazy=True)

    def __repr__(self):
        return '<Trip %r>' % self.id
    
    def serialize(self):
        return {
            "id": self.id,
            "country": self.country,
            "city": self.city,
            "activities": self.activities
        }

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    Address = db.Column(db.String(200), nullable=False)
    dni = db.Column(db.Integer, nullable=False)
    location = db.Column(db.Integer, nullable=False)
    payment_method = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

    def serialize(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "firstname": self.firstname,
            "lastname": self.lastname,
            "Address": self.Address,
            "dni": self.dni,
            "location": self.location,
            "payment_method": self.payment_method,
        }

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    trip_id = db.Column(db.Integer, nullable=False)
    comment_text = db.Column(db.String(500), nullable=False)

    def __repr__(self):
        return '<Review %r>' % self.id

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "trip_id": self.trip_id,
            "comment_text": self.comment_text
        }
    
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, nullable=False)
    review_id = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<Post %r>' % self.id

    def serialize(self):
        return {
            "id": self.id,
            "author_id": self.author_id,
            "review_id": self.review_id
        }
    
class Favorites(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    trip_id = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<Favorites %r>' % self.id

    def serialize(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "trip_id": self.trip_id
        }
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=True)  # Vous pouvez définir la valeur par défaut à True si nécessaire

    def __repr__(self):
        return '<Admin %r>' % self.username

    def serialize(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_admin": self.is_admin
        }


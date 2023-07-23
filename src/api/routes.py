"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint, redirect
from api.models import db, User, Business_user, Post, Favorites, Review, Offers, Trip, Admin
from api.utils import generate_sitemap, APIException
from flask_bcrypt import bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager, unset_jwt_cookies
from sqlalchemy.orm.exc import NoResultFound

def initialize_jwt(api):
    jwt.init_app(api)
api = Blueprint('api', __name__)

jwt = JWTManager()



from api.models import db, User, Business_user

@api.route('/signup', methods=['POST'])
def add_new_user():
    body = request.get_json()

    user_type = body.get("user_type")  # Ajoutez un champ "user_type" au JSON de la requête

    if not user_type or user_type not in ['user', 'business']:
        return jsonify({'error': 'Invalid user_type. Must be either "user" or "business".'}), 400

    # Sélectionnez la classe appropriée en fonction du type d'utilisateur
    if user_type == 'user':
        UserClass = User
    else:
        UserClass = Business_user

    user_exist = UserClass.query.filter_by(email=body.email).first()

    if user_exist:
        return jsonify({'error': 'Email already exists.'}), 403

    pw_hash = bcrypt.generate_password_hash(body.password).decode('utf-8')

    new_user = UserClass(
        email=body.email,
        password=pw_hash
    )

    if user_type == 'business':
        # Si c'est un utilisateur "Business_user", configurez les champs supplémentaires ici
        new_user.business_name = body.get("business_name")
        new_user.nif = body.get("nif")
        new_user.address = body.get("address")
        new_user.payment_method = body.get("payment_method")

    db.session.add(new_user)
    db.session.commit()

    response_body = {
        "message": "User created successfully",
        "user": new_user.serialize()
    }
    return jsonify(response_body), 200

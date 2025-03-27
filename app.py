from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, set_access_cookies
from flask_migrate import Migrate
import google.auth.transport.requests as google_requests
from google.oauth2 import id_token
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:Ankitha%40123@localhost:5432/letter_app"
app.config["GOOGLE_CLIENT_ID"] = "523505597802-scp7asjjni0hq0vdqlc1oes2qqtg3uus.apps.googleusercontent.com"
app.config["GOOGLE_CLIENT_SECRET"] = "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"
app.config["GOOGLE_REDIRECT_URI"] = "http://localhost:5000/auth/callback"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False  
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token_cookie"
# app.config["JWT_ALGORITHM"] = "RS256"

jwt = JWTManager(app)

CORS(app, supports_credentials=True)
db = SQLAlchemy(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

# Models
class User(db.Model):
    id = db.Column(db.String(255), primary_key=True)  # Changed from Integer to String
    google_id = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)

class Letter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(255), db.ForeignKey('users.id'), nullable=False)  # Changed reference to match table name
    title = db.Column(db.String(255))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_uploaded = db.Column(db.Boolean, default=False)



# Routes
@app.route("/auth/google", methods=["POST"])
def google_login():
    token = request.json.get("token")
    try:
        user_info = id_token.verify_oauth2_token(token, google_requests.Request(), app.config["GOOGLE_CLIENT_ID"])
        email = user_info["email"]
        google_id = user_info["sub"]
        name = user_info.get("name", "User")

        user = User.query.filter_by(google_id=google_id).first()
        if not user:
            user = User(google_id=google_id, email=email, name=name)
            db.session.add(user)
            try:
                db.session.commit()
                print("User saved successfully:", user.email)  # Debugging
            except Exception as e:
                db.session.rollback()
                print("Database Commit Error:", str(e))  # Print any errors

        access_token = create_access_token(identity=google_id)
        response = make_response(jsonify({"success": True}))
        response.set_cookie("token", access_token, httponly=True, secure=False, samesite="Lax")
        set_access_cookies(response, access_token)
        return response
    except Exception as e:
        print("Error:", str(e))
        return jsonify({"error": "Invalid token"}), 401


@app.route("/auth/validate", methods=["GET"])
@jwt_required()
def validate_session():
    user_id = get_jwt_identity()
    user = User.query.filter_by(google_id=user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"success": True, "user": {"name": user.name, "email": user.email}})

@app.route("/auth/logout", methods=["POST"])
def logout():
    response = make_response(jsonify({"message": "Logged out successfully"}))
    response.set_cookie("token", "", expires=0, httponly=True)
    return response

@app.route("/letters", methods=["GET"])
@jwt_required()
def get_letters():
    user_id = get_jwt_identity()
    letters = Letter.query.filter_by(user_id=str(user_id)).all()

    if not letters:
        return jsonify({"message": "No letters found"}), 404

    return jsonify([{"id": l.id, "title": l.title, "content": l.content} for l in letters])


@app.route("/debug", methods=["GET"])
@jwt_required()
def debug_jwt():
    return jsonify({
        "user": get_jwt_identity(),
        "jwt": get_jwt()
    })

@app.route("/letters/save", methods=["POST"])
@jwt_required()
def save_letter():
    user_id = get_jwt_identity()
    data = request.json
    new_letter = Letter(user_id=user_id, title=data.get("title", "Untitled"), content=data["content"])
    db.session.add(new_letter)
    db.session.flush()
    db.session.commit()
    return jsonify({"message": "Letter saved successfully!"})

@app.route("/letters/<int:letter_id>", methods=["PUT"])
@jwt_required()
def update_letter(letter_id):
    user_id = get_jwt_identity()
    letter = Letter.query.filter_by(id=letter_id, user_id=user_id).first()
    if not letter:
        return jsonify({"error": "Letter not found"}), 404

    data = request.json
    letter.title = data.get("title", letter.title)
    letter.content = data.get("content", letter.content)
    db.session.commit()
    return jsonify({"message": "Letter updated successfully!"})

@app.route("/")
def home():
    return "Welcome to Letter App1!"

if __name__ == "__main__":
    app.run(debug=True)

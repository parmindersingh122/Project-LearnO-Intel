from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Configurations
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lerno.db"
app.config["SECRET_KEY"] = "nitro120"
app.config["JWT_SECRET_KEY"] = "your_jwt_secret_key"  # Add this
db = SQLAlchemy(app)
jwt = JWTManager(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), default="user", nullable=False)  # 'admin' or 'user'
    registered_on = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

# Ensure database is created
with app.app_context():
    db.create_all()

# Register a user
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")  # Default to "user"

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "User already exists"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully", "role": role}), 201

# User login
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password"}), 401

    # Update last login time
    user.last_login = datetime.utcnow()
    db.session.commit()

    # Generate JWT token
    access_token = create_access_token(identity=user.username, additional_claims={"role": user.role})
    return jsonify({"message": "Login successful", "token": access_token}), 200

# Dashboard route (User & Admin Views)
@app.route("/dashboard", methods=["GET"])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()  # Get username
    role = get_jwt()["role"]  # Get role separately

    user = User.query.filter_by(username=current_user).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    user_data = {
        "username": user.username,
        "user_id": user.id,
        "role": user.role,
        "registered_on": user.registered_on.strftime("%Y-%m-%d %H:%M:%S"),
        "last_login": user.last_login.strftime("%Y-%m-%d %H:%M:%S") if user.last_login else "Never",
        "message": f"Welcome, {user.username}!"
    }

    if role == "admin":
        users = User.query.all()
        all_users = [
            {
                "user_id": u.id,
                "username": u.username,
                "role": u.role,
                "registered_on": u.registered_on.strftime("%Y-%m-%d %H:%M:%S"),
                "last_login": u.last_login.strftime("%Y-%m-%d %H:%M:%S") if u.last_login else "Never"
            }
            for u in users
        ]
        user_data["all_users"] = all_users
        user_data["total_users"] = len(users)

    return jsonify(user_data), 200

# Home route
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Lerno API is running!"})

if __name__ == "__main__":
    app.run(debug=True)

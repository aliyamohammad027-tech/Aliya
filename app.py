from flask import Flask, request, jsonify,render_template
import psycopg2
from psycopg2 import sql
from flask_bcrypt import Bcrypt
import jwt
import datetime

app = Flask(__name__, template_folder='templates')

bcrypt = Bcrypt(app)

# Secret Key
SECRET_KEY = "this is my secret key this is my secret key!!"

# JWT Functions
def create_jwt(user_id, username):
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=20)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_jwt(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except:
        return None

# Database Configuration
DB_HOST = 'localhost'
DB_NAME = 'postgres'
DB_USER = 'postgres'
DB_PASSWORD = '1227'

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

# Create Users Table
def create_users_table():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users_dbs(
            user_id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

@app.route("/")
def index():
    return render_template('login.html')
@app.route("/login_page")
def login_page():
    return render_template('login.html')

@app.route("/signup_page")
def signup_page():
    return render_template('signup.html')

@app.route("/dashboard_page")
def dashboard_page():
    return render_template('dashboard.html')

# SIGNUP
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    hashed = bcrypt.generate_password_hash(password).decode("utf-8")
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO users_dbs(username,email,password)
        VALUES(%s,%s,%s) 
        RETURNING user_id
    """, (username, email, hashed))
    user_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    token = create_jwt(user_id, username)
    return jsonify({"message": "Signup successful", "token": token})

# LOGIN API 
@app.route("/login", methods=["POST"])
def login():

    data = request.json

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "All fields required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT user_id, username, password
        FROM users_dbs
        WHERE email = %s
    """, (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    user_id, username, hashed_password = user

    # Verify Password
    if not bcrypt.check_password_hash(hashed_password, password):
        return jsonify({"error": "Invalid password"}), 401

    # Create Token
    token = create_jwt(user_id, username)

    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "user_id": user_id,
            "username": username,
            "email": email
        }
    }), 200


if __name__ == "__main__":
    app.run(debug=True)
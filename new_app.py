from flask import Flask, request, jsonify
import psycopg2
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
bcrypt = Bcrypt(app)


SECRET_KEY = "this is my secret key this is my secret key!!"

DB_HOST = "localhost"
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PASSWORD = "1227"



def jwt_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )



def create_jwt(user_id, username):
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_jwt(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None





def create_tables():
    conn = jwt_db_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users_dbs (
            user_id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS student_forms (
            form_id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES  users_dbs(user_id),
            full_name TEXT,
            age TEXT,
            course TEXT
        );
    """)

    conn.commit()
    cur.close()
    conn.close()


create_tables()



@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        conn = jwt_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO  users_dbs (username, email, password)
            VALUES (%s, %s, %s)
            RETURNING user_id
        """, (username, email, hashed_password))

        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        token = create_jwt(user_id, username)

        return jsonify({
            "message": "Signup successful",
            "token": token
        }), 201

    except psycopg2.Error:
        return jsonify({"error": "Email already exists"}), 409



# LOGIN API

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "All fields required"}), 400

    conn = jwt_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT user_id, username, password
        FROM  users_dbs
        WHERE email = %s
    """, (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    user_id, username, hashed_password = user

    if not bcrypt.check_password_hash(hashed_password, password):
        return jsonify({"error": "Invalid password"}), 401

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


@app.route("/apply", methods=["POST"])
def apply():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error":"token invalid"}), 401

    user_data = verify_jwt(token)

    if user_data is None:
        return jsonify({"error":"Invalid or expired token"}), 401
    
    full_name = request.json["full_name"]
    age = request.json["age"]
    course = request.json["course"]

    connection  = jwt_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
                INSERT INTO student_forms(user_id, full_name, age, course)
                VALUES(%s, %s, %s, %s);
""",(user_data["user_id"], full_name, age,course))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message":"application submitted"}), 201

@app.route("/get_apply",methods =['GET'])
def get_apply():
    token = request.headers.get("Authorization")

    if not token :
        return jsonify({"error":"token invaild"}),401
    user_data = verify_jwt(token)

    if user_data is None:
        return jsonify({"error": "Invalid or expired token"}), 401
    connection = jwt_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
           SELECT form_id,full_name,age,course 
           FROM student_forms where user_id =%s;
                   
""",(user_data["user_id"],))
    user = cursor.fetchall()
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({
        "user":user_data["username"],
        "Form":[
            {
                "form_id":f[0],
                "fullname":f[1],
                "age":f[2],
                "course":f[3]
            } for f in user
        ]
    }),201

@app.route("/update_apply/<int:form_id>",methods =['PUT'])
def update_apply(form_id):
    token = request.headers.get("Authorization")

    if not token :
        return jsonify({"error":"token invaild"}),401
    user_data = verify_jwt(token)
    if user_data is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    full_name =request.json['full_name']
    age =request.json['age']
    course = request.json['course']
    connection = jwt_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            SELECT * FROM student_forms  where form_id =%s AND user_id =%s
""",(form_id,user_data['user_id']))
    cursor.fetchone()
    cursor.execute("""
           UPDATE student_forms SET full_name=%s,age=%s,course=%s 
           WHERE form_id=%s ;                  
""",(full_name, age,course,form_id))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message":"application updated"}),201

@app.route("/delete_apply/<int:form_id>",methods =['DELETE'])
def delete_apply(form_id):
    token = request.headers.get("Authorization")

    if not token :
        return jsonify({"error":"token invaild"}),401
    user_data = verify_jwt(token)
    if user_data is None:
        return jsonify({"error": "Invalid or expired token"}), 401

    connection = jwt_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
            SELECT * FROM student_forms  where form_id =%s AND user_id =%s
""",(form_id,user_data['user_id']))
    cursor.fetchone()
    cursor.execute("""
           DELETE  FROM student_forms WHERE form_id=%s ;
                   
""",(form_id,))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message":"Form deleted successfully"}),201


if __name__ == "__main__":
    app.run(debug=True)

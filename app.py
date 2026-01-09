from flask import Flask , request , jsonify
import psycopg2
from psycopg2 import sql

app = Flask(__name__)

#database configuration
DB_HOST='localhost'
DB_NAME='postgres'
DB_USER='postgres'
DB_PASSWORD='1227'

def get_db_connection():
    connection=psycopg2.connect(
    host=DB_HOST,
    database=DB_NAME,
    user=DB_USER,
    password=DB_PASSWORD
)
    return connection
def create_tb_if_not_exist():
    connection = get_db_connection()
    cursor = connection.cursor()
  
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
    user_id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL
        );   
    """)
    connection.commit()
    cursor.close()
    connection.close()
create_tb_if_not_exist()

@app.route("/user_register", methods=['POST'])
def user_register():
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
         INSERT INTO users(username, password, email)
         VALUES(%s, %s, %s)
""", (username, password, email))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message":"User registered successfully"}),200

@app.route("/get_users",methods = ['GET'])
def get_users():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
             SELECT * FROM users;
    """)
    user_id = cursor.fetchall()
    cursor.close()
    connection.close()
    result =[
            {"user_id":user[0],
            "username":user[1],
            "password":user[2],
            "email":user[3]} for user in user_id
    ]
    return jsonify(result),200

@app.route('/user_update',methods = ['PUT'])
def user_update():
    user_id = request.args.get('user_id')
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
          UPDATE users
                    SET username=%s, password = %s,email = %s where user_id = %s;
""",(username,password,email,user_id))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message":"user update successfully"}),201


@app.route('/delete_user',methods=['DELETE'])
def delete_user():
    user_id = request.args.get('user_id')
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        DELETE FROM users WHERE user_id=%s;
    """,(user_id,))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message":"user deleted successfully"}),200


if  __name__=='__main__':
   app.run(debug = True)

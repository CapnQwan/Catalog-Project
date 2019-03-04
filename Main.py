from flask import Flask, render_template, url_for, request, jsonify, json, redirect, g
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from DB_setup import Base, User
from flask.ext.httpauth import HTTPBasicAuth
import requests
from flask import session as login_session


app = Flask(__name__)


engine = create_engine('sqlite:///Catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/Corvus')
def homepage():
	try:
		print(login_session['Username'])
		return render_template('front_page.html')
	except:
		return render_template('front_page.html')


@app.route('/Corvus/login', methods = ['GET', 'POST'])
def Login():
	if  request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		if username is None or password is None:
			return render_template('Login.html')
		userlogin = session.query(User).filter_by(username=username).first()
		if not userlogin or not userlogin.verify_password(password):
			print(userlogin)
			return render_template('Login.html')
		else:
			g.userlogin = userlogin
			token = g.userlogin.generate_auth_token()
			login_session['Username'] = username
			login_session['Usertoken'] = token
			return redirect(url_for('homepage'))
	else:	
		return render_template('Login.html')


@app.route('/Corvus/signup', methods = ['GET', 'POST'])
def Signup():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		email = request.form['email']
		if username is None or password is None or email is None:
			return render_template('Sign_up.html')

		if session.query(User).filter_by(username=username).first() is not None:
			return render_template('Sign_up.html')

		user = User(username = username, email = email)
		user.hash_password(password)
		session.add(user)
		session.commit()
		g.user = user
		token = g.user.generate_auth_token()
		login_session['Username'] = username
		login_session['Usertoken'] = token
		return redirect(url_for('homepage'))
	else:
		return render_template('Sign_up.html')

@app.route('/Corvus/Logout')
def Logout():
	del login_session['Username']
	del login_session['Usertoken']
	return redirect(url_for('homepage'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

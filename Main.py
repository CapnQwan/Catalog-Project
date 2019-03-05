from flask import Flask, render_template, url_for, request, jsonify, json, redirect, g
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from DB_setup import Base, User, CatalogItem
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
			return render_template('Login.html')
		else:
			token = userlogin.generate_auth_token()
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
	try:
		del login_session['Username']
		del login_session['Usertoken']
		return redirect(url_for('homepage'))
	except:
		return redirect(url_for('homepage'))

@app.route('/Corvus/Newitem', methods = ['GET', 'POST'])
def Newitem():
	try:
		t = login_session['Usertoken']
		user_id = User.verify_auth_token(t)
		print(user_id)
		if request.method == 'POST':
			if user_id:
				name = request.form['Name']
				desc = request.form['description']
				price = request.form['price']
				catagory = request.form['catagory']
				newitem = CatalogItem(name = name, catagory = catagory, description = desc, price = price, user_id = user_id)
				session.add(newitem)
				session.commit()
				print('item added')
				return redirect(url_for('homepage'))
			else: 
				print('must be logged in')
				return redirect(url_for('signup'))
		else:
		
			return render_template('New_item.html')
	except:
		print('invalid token')
		return redirect(url_for('homepage'))

@app.route('/Corvus/Item/<int:item_id>/')
def ViewItem(item_id):
	item = session.query(CatalogItem).filter_by(id=item_id).one()
	return render_template('item.html', item=item)

#this was added as i struck a problem with the newitem function so this was there to test the token
@app.route('/token')
def get_auth_token():
    token = login_session['token']
    return jsonify({'token': token.decode('ascii')})


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

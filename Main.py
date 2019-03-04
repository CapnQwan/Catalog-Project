from flask import Flask, render_template, url_for, request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from DB_setup import Base, User
from flask.ext.httpauth import HTTPBasicAuth


app = Flask(__name__)


engine = create_engine('sqlite:///Catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/Corvus')
def homepage():
	return render_template('front_page.html')


@app.route('/Corvus/login')
def Login():
	return render_template('Login.html')


@app.route('/Corvus/signup', methods = ['GET', 'POST'])
def Signup():
	if request.method == 'POST':
		username = request.json.get('username')
		password = request.json.get('password')
		email = request.json.get('email')
		if username in None or password is None:
			render_template('Signup.html')

		if session.query(User).filter_by(username=username).first is not None:
			render_template('Signup.html')

		user = User(username = username, email = email)
		user.hash_password(password)
		session.add(user)
		session.commit()
		return redirect(url_for('/Corvus'))
	else:
		return render_template('Sign_up.html')


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

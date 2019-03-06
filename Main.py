from flask import Flask, render_template, url_for, request, jsonify, json, redirect, make_response, g
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from DB_setup import Base, User, CatalogItem
from flask.ext.httpauth import HTTPBasicAuth
import requests, httplib2, json, string, random
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError


app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

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
		state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
		login_session['state'] = state
		return render_template('Login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    print("start")
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        print('error1')
        return response
    # Obtain authorization code, now compatible with Python3
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
    	oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
    	oauth_flow.redirect_uri = 'postmessage'
    	credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        print('error2')
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        print('error3')
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        print('error4')
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print('error5')
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id
    login_session['provider'] = 'google'

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['Username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    try:
    	user = session.query(User).filter_by(email=login_session['email']).one()
        login_session['user_id'] = user.id
        print('logged in')
    except:
    	user = None
    if not user:
        Newuser = User(username = login_session['Username'], email = login_session['email'])
        session.add(Newuser)
        session.commit()
        login_session['user_id'] = Newuser.id
    return output


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
	if 'provider' in login_session:
		print('1')
		if login_session['provider'] == 'google':
			print('2')
			gdisconnect()
			return redirect(url_for('homepage'))
			#return redirect('https://www.google.com/accounts/Logout?continue=https://appengine.google.com/_ah/logout?continue=http://localhost:5000/Corvus')
	else:
		try:
			del login_session['Username']
			del login_session['Usertoken']
			return redirect(url_for('homepage'))
		except:
			return redirect(url_for('homepage'))


@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print(result['status'])
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['Username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


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
				return redirect(url_for('ViewItem', item_id=newitem.id))
			else: 
				print('must be logged in')
				return redirect(url_for('signup'))
		else:
			return render_template('New_item.html')
	except:
		print('invalid token')
		return redirect(url_for('homepage'))


@app.route('/Corvus/Profile')
def Profile():
	try:
		t = login_session['Usertoken']
		user_id = User.verify_auth_token(t)
		items = session.query(CatalogItem).filter_by(user_id=user_id).all()
		user = session.query(User).filter_by(id=user_id).one()
		return render_template('Users_items.html', items=items, user=user)
	except:
		return redirect(url_for('Login'))	


@app.route('/Corvus/Item/<int:item_id>/')
def ViewItem(item_id):
	item = session.query(CatalogItem).filter_by(id=item_id).one()
	usersitem = session.query(User).filter_by(id=item.user_id).one()
	try:
		t = login_session['Usertoken']
		user_id = User.verify_auth_token(t)
		if user_id == item.user_id:
			return render_template('Owner_item.html', item=item)
		else:
			return render_template('item.html', item=item, useritem=usersitem)
	except:
		return render_template('item.html', item=item, useritem=usersitem)


@app.route('/Corvus/catagory/<string:catagory_Type>')
def ViewCatagory(catagory_Type):
	if catagory_Type == 'All products':
		Ctype = session.query(CatalogItem).all()
	else:
		Ctype = session.query(CatalogItem).filter_by(catagory=catagory_Type).all()
	return render_template('catagory.html', items=Ctype, catagory=catagory_Type)


@app.route('/Corvus/Item/<int:item_id>/Edit', methods = ['GET', 'POST'])
def EditItem(item_id):
	edit_item = session.query(CatalogItem).filter_by(id=item_id).one()
	try:
		t = login_session['Usertoken']
		user_id = User.verify_auth_token(t)
		if user_id == edit_item.user_id:
			if request.method == 'POST':
				if request.form['Name'] and request.form['price'] and request.form['description']:
					edit_item.name = request.form['Name']
					edit_item.price = request.form['price']
					edit_item.catagory = request.form['catagory']
					edit_item.description = request.form['description']
					return redirect(url_for('ViewItem', item_id=edit_item.id))
			else:
				return render_template('Edit_item.html', item=edit_item)
		else:
			return redirect(url_for('Login'))
	except:
		return redirect(url_for('Login'))


@app.route('/Corvus/Item/<int:item_id>/Del', methods=["GET", "POST"])
def DelItem(item_id):
	delete_item = session.query(CatalogItem).filter_by(id=item_id).one()
	try:
		t = login_session['Usertoken']
		user_id = User.verify_auth_token(t)
		if user_id == delete_item.user_id:
			if request.method == 'POST':
				session.delete(delete_item)
				session.commit()
				return redirect(url_for('homepage'))
			else:
				return render_template('Delete_item.html', item=delete_item)
		else:
			return redirect(url_for('Login'))
	except:
		return redirect(url_for('Login'))


@app.route('/Corvus/User/<int:User_id>')
def UsersUploads(User_id):
	items = session.query(CatalogItem).filter_by(user_id=User_id).all()
	user = session.query(User).filter_by(id=User_id).one()
	return render_template('Users_items.html', items=items, user=user)


#this was added as i struck a problem with the newitem function so this was there to test the token
@app.route('/token')
def get_auth_token():
    token = login_session['token']
    return jsonify({'token': token.decode('ascii')})


@app.route('/Corvus/Item/<int:item_id>/JSON')
def ItemJSON(item_id):
	item = session.query(CatalogItem).filter_by(id=item_id).one()
	return jsonify(items=item.serialize)


@app.route('/Corvus/JSON')
def ItemsJSON():
	items = session.query(CatalogItem).all()
	return jsonify(items=[i.serialize for i in items])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

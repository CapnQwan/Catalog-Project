from flask import Flask, render_template, url_for, request, jsonify, json, redirect, make_response, g
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from DB_setup import Base, User, CatalogItem
from flask.ext.httpauth import HTTPBasicAuth
import requests, httplib2, json, string, random, os
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = 'static/Upload images'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

engine = create_engine('sqlite:///Catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def testlogin():
	try:
		print(login_session['provider'])
		if login_session['provider'] == 'Corvus':
			t = login_session['Usertoken']
			user_id = User.verify_auth_token(t)
			user = session.query(User).filter_by(id=user_id).one()
			return user
		elif login_session['provider'] == 'google':
			user = session.query(User).filter_by(email=login_session['email']).one()
			return user
	except:
		return None


@app.route('/')
@app.route('/Corvus')
def homepage():
	userlogin = testlogin()
	items = session.query(CatalogItem).order_by(desc(CatalogItem.View)).limit(4).all()
	try:
		print(userlogin.username)
	except:
		print('no user')
	finally:
		return render_template('front_page.html', items=items, userlogin=userlogin)



@app.route('/Corvus/login', methods = ['GET', 'POST'])
def Login():
	userlogin = testlogin()
	if  request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		if username is None or password is None:
			return render_template('Login.html', userlogin=userlogin)
		userlogin = session.query(User).filter_by(username=username).first()
		if not userlogin or not userlogin.verify_password(password):
			return render_template('Login.html', userlogin=userlogin)
		else:
			token = userlogin.generate_auth_token()
			login_session['Username'] = username
			login_session['Usertoken'] = token
			login_session['provider'] = 'Corvus'
			return redirect(url_for('homepage'))
	else:
		state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
		login_session['state'] = state
		return render_template('Login.html', STATE=state, userlogin=userlogin)


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
        Newuser = User(username = login_session['Username'], email = login_session['email'], profilepic = login_session['picture'])
        session.add(Newuser)
        session.commit()
        login_session['user_id'] = Newuser.id
    return redirect(url_for('homepage'))


@app.route('/Corvus/signup', methods = ['GET', 'POST'])
def Signup():
	userlogin = testlogin()
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		email = request.form['email']
		if username is None or password is None or email is None:
			return render_template('Sign_up.html', userlogin=userlogin)

		if session.query(User).filter_by(username=username).first() is not None:
			return render_template('Sign_up.html', userlogin=userlogin)

		user = User(username = username, email = email)
		user.hash_password(password)
		session.add(user)
		session.commit()
		g.user = user
		token = g.user.generate_auth_token()
		login_session['Username'] = username
		login_session['Usertoken'] = token
		login_session['provider'] = 'Corvus'
		return redirect(url_for('homepage'))
	else:
		return render_template('Sign_up.html', userlogin=userlogin)

@app.route('/Corvus/Logout')
def Logout():
	try: 
		if login_session['provider'] == 'Corvus':
			del login_session['Username']
			del login_session['Usertoken']
			del login_session['provider']
		elif login_session['provider'] == 'google':
			print('1')
			gdisconnect()
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
        del login_session['provider']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



@app.route('/Corvus/Newitem', methods = ['GET', 'POST'])
def Newitem():
	userlogin = testlogin()
	if userlogin != None:
		if request.method == 'POST':
			name = request.form['Name']
			desc = request.form['description']
			price = request.form['price']
			catagory = request.form['catagory']
			file = request.files['file']
			if file.filename == '':
				return redirect(url_for('Newitem'))
			if file and allowed_file(file.filename):
				filename = secure_filename(file.filename)
				file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
				views = 0
				newitem = CatalogItem(name = name, catagory = catagory, description = desc, price = price, user_id = userlogin.id, View=views, filename=filename)
				session.add(newitem)
				session.commit()
				print('item added')
				return redirect(url_for('ViewItem', item_id=newitem.id))
			return redirect(url_for('Newitem'))
		else:
			return render_template('New_item.html', userlogin=userlogin)
	else:
		return redirect(url_for('homepage'))


@app.route('/Corvus/Profile', methods = ['GET', 'POST'])
def Profile():
	userlogin = testlogin()
	if userlogin != None:
		items = session.query(CatalogItem).filter_by(user_id=userlogin.id).all()
		if request.method == 'POST':
			formname = request.form['form-name']
			if formname == 'form1':
				userlogin.description = request.form['description']
				return render_template('Profile.html', items=items, user=userlogin, userlogin=userlogin)	
			elif formname == 'form2':
				file = request.files['file']
				if file.filename == '':
					return render_template('profile.html', items=items, user=userlogin, userlogin=userlogin)
				if file and allowed_file(file.filename):
					filename = secure_filename(file.filename)
					file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
					userlogin.profilepic = filename
					return render_template('Profile.html', items=items, user=userlogin, userlogin=userlogin)	
		return render_template('Profile.html', items=items, user=userlogin, userlogin=userlogin)
	else:
		return redirect(url_for('Login'))	


@app.route('/Corvus/Item/<int:item_id>/')
def ViewItem(item_id):
	userlogin = testlogin()
	item = session.query(CatalogItem).filter_by(id=item_id).one()
	usersitem = session.query(User).filter_by(id=item.user_id).one()
	if userlogin != None:
		if userlogin.id == item.user_id:
			return render_template('Owner_item.html', item=item, userlogin=userlogin)
		else:
			views = item.View
			views = views + 1
			item.View = views
			return render_template('item.html', item=item, useritem=usersitem, userlogin=userlogin)
	else:
		return render_template('item.html', item=item, useritem=usersitem, userlogin=userlogin)


@app.route('/Corvus/catagory/<string:catagory_Type>')
def ViewCatagory(catagory_Type):
	userlogin = testlogin()
	if catagory_Type == 'All products':
		Ctype = session.query(CatalogItem).all()
	else:
		Ctype = session.query(CatalogItem).filter_by(catagory=catagory_Type).all()
	return render_template('catagory.html', items=Ctype, catagory=catagory_Type, userlogin=userlogin)


@app.route('/Corvus/Item/<int:item_id>/Edit', methods = ['GET', 'POST'])
def EditItem(item_id):
	userlogin = testlogin()
	edit_item = session.query(CatalogItem).filter_by(id=item_id).one()
	if userlogin != None:
		if userlogin.id == edit_item.user_id:
			if request.method == 'POST':
				if request.form['Name'] and request.form['price'] and request.form['description']:
					edit_item.name = request.form['Name']
					edit_item.price = request.form['price']
					edit_item.catagory = request.form['catagory']
					edit_item.description = request.form['description']
					return redirect(url_for('ViewItem', item_id=edit_item.id))
				else:
					return render_template('Edit_item.html', item=edit_item, userlogin=userlogin)
			else:
				return render_template('Edit_item.html', item=edit_item, userlogin=userlogin)
		else:
			return redirect(url_for('Login'))
	else:
		return redirect(url_for('Login'))


@app.route('/Corvus/Item/<int:item_id>/Del', methods=["GET", "POST"])
def DelItem(item_id):
	userlogin = testlogin()
	delete_item = session.query(CatalogItem).filter_by(id=item_id).one()
	if userlogin != None:
		if userlogin.id == delete_item.user_id:
			if request.method == 'POST':
				session.delete(delete_item)
				session.commit()
				return redirect(url_for('homepage'))
			else:
				return render_template('Delete_item.html', item=delete_item, userlogin=userlogin)
		else:
			return redirect(url_for('Login'))
	else:
		return redirect(url_for('Login'))


@app.route('/Corvus/User/<int:User_id>')
def UsersUploads(User_id):
	userlogin = testlogin()
	items = session.query(CatalogItem).filter_by(user_id=User_id).all()
	user = session.query(User).filter_by(id=User_id).one()
	return render_template('Users_items.html', items=items, user=user, userlogin=userlogin)


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


@app.route('/fdc')
def ForeDC():
	del login_session['access_token']
	del login_session['gplus_id']
	del login_session['Username']
	del login_session['email']
	del login_session['picture']
	del login_session['provider']
	return redirect(url_for('homepage'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

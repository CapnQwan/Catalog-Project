from flask import Flask, render_template, url_for, request
from flask import jsonify, json, redirect, make_response, g
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from DB_setup import Base, User, CatalogItem
from flask.ext.httpauth import HTTPBasicAuth
import requests
import httplib2
import json
import string
import random
import os
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from werkzeug.utils import secure_filename


# This sets up the directory for any uploaded imaages
UPLOAD_FOLDER = 'static/Upload images'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# this sets up googles login IDs
CLIENT_ID = json.loads(open('client_secrets.json',
                            'r').read())['web']['client_id']


engine = create_engine('sqlite:///Catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# this is used to test if the user is logged in and if
# they are logged in with google or corvus
def testlogin():
    try:
        if login_session['provider'] == 'Corvus':
            t = login_session['Usertoken']
            user_id = User.verify_auth_token(t)
            user = session.query(User).filter_by(id=user_id).one()
            return user
        elif login_session['provider'] == 'google':
            user = session.query(User
                                 ).filter_by(email=login_session['email']
                                             ).one()
            return user
    except:
        return None


# the homepage/front page for corvus
@app.route('/')
@app.route('/Corvus')
def homepage():
    userlogin = testlogin()
    items = session.query(CatalogItem).order_by(desc(
                            CatalogItem.View)).limit(4).all()
    try:
        print(userlogin.username)
    except:
        print('no user')
    finally:
        return render_template('front_page.html', items=items,
                               userlogin=userlogin)


# the login function that checks if the method is POST whether the username
# form and password form are blank if not then it checks if the password hash
# is the same as the password entered otherwise if its a GET request it sets up
# the state for an extra layer of security then renders the template
@app.route('/Corvus/login', methods=['GET', 'POST'])
def Login():
    userlogin = testlogin()
    if request.method == 'POST':
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
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in range(32))
        login_session['state'] = state
        return render_template('Login.html', STATE=state, userlogin=userlogin)


# this is the function used to login users in with google
@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data.decode('utf-8')

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps
                                 ('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id
    login_session['provider'] = 'google'

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['Username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    try:
        user = session.query(User
                             ).filter_by(email=login_session['email']).one()
        login_session['user_id'] = user.id
    except:
        user = None
    if not user:
        Newuser = User(username=login_session['Username'],
                       email=login_session['email'])
        session.add(Newuser)
        session.commit()
        login_session['user_id'] = Newuser.id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['Username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius:'
    output += ' 150px;-webkit-border-radius: '
    output += '150px;-moz-border-radius: 150px;"> '
    return output


# this is used to sign up it checks if the method is POST then it gets the
# email username and password then checks if they are empty if they are not
# it then checks if the username is already taken if not it will hash the
# password and adds the user to the database and logs them in
@app.route('/Corvus/signup', methods=['GET', 'POST'])
def Signup():
    userlogin = testlogin()
    if request.method == 'POST':
        if (request.form['username'] == '' or
                request.form['password'] == '' or request.form['email'] == ''):
            return render_template('Sign_up.html', userlogin=userlogin)
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        if session.query(User).filter_by(username=username
                                         ).first() is not None:
            return render_template('Sign_up.html', userlogin=userlogin)

        user = User(username=username, email=email)
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


# checks if the user is logged in with
# corvus or google if they are logged
# in with google it the runs gdisconnect
# otherwise if they are logged in with
# with corvus is removes there login state
@app.route('/Corvus/Logout')
def Logout():
    try:
        if login_session['provider'] == 'Corvus':
            del login_session['Username']
            del login_session['Usertoken']
            del login_session['provider']
        elif login_session['provider'] == 'google':
            gdisconnect()
        return redirect(url_for('homepage'))
    except:
        return redirect(url_for('homepage'))


# this dissconects the user from google by
# revoking there token and then
# removes the login states of the user
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
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


# checks if a file is okay file type
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# this is to add a new item to the catalog
# database first it checks if the user is logged in
# if they are then it checks if the method is
# a POST request if it is it checks if all the feilds
# are populated if they are it then checks the
# filename which if thats ok it saves the file sets
# views to 0 and addeds the item to the database
# and redirects the user to the new webpage
@app.route('/Corvus/Newitem', methods=['GET', 'POST'])
def Newitem():
    userlogin = testlogin()
    if userlogin is not None:
        if request.method == 'POST':
            name = request.form['Name']
            desc = request.form['description']
            price = request.form['price']
            catagory = request.form['catagory']
            file = request.files['file']
            if (file.filename == '' or name == '' or desc == '' or
                    price == '' or catagory == ''):
                return redirect(url_for('Newitem'))
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                views = 0
                newitem = CatalogItem(name=name, catagory=catagory,
                                      description=desc,
                                      price=price, user_id=userlogin.id,
                                      View=views,
                                      filename=filename)
                session.add(newitem)
                session.commit()
                return redirect(url_for('ViewItem', item_id=newitem.id))
            return render_template('New_item.html', userlogin=userlogin)
        else:
            return render_template('New_item.html', userlogin=userlogin)
    else:
        return redirect(url_for('homepage'))


# on this page you can change your profile picture
# and description on your profile using
# similar forms as before and you can see all
# the items that you have uploaded
@app.route('/Corvus/Profile', methods=['GET', 'POST'])
def Profile():
    userlogin = testlogin()
    if userlogin is not None:
        items = session.query(CatalogItem
                              ).filter_by(user_id=userlogin.id).all()
        if request.method == 'POST':
            formname = request.form['form-name']
            if formname == 'form1':
                userlogin.description = request.form['description']
                session.add(userlogin)
                session.commit()
                return render_template('Profile.html', items=items,
                                       user=userlogin,
                                       userlogin=userlogin)
            elif formname == 'form2':
                file = request.files['file']
                if file.filename == '':
                    return render_template('profile.html', items=items,
                                           user=userlogin,
                                           userlogin=userlogin)
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'],
                              filename))
                    userlogin.profilepic = filename
                    session.add(userlogin)
                    session.commit()
                    return render_template('Profile.html', items=items,
                                           user=userlogin,
                                           userlogin=userlogin)
        return render_template('Profile.html', items=items, user=userlogin,
                               userlogin=userlogin)
    else:
        return redirect(url_for('Login'))


# on this route the server take the item ID from
# the uri and will check the database form the
# item with the same ID if the ID is not in the
# database it wil redirect the user to the homepage
# otherwise if the item ID is in the database it
# will check if the user accessing it is the same
# user that made it if this is the case it will
# render a template that allows you to edit or delete
# the item where if the user is not the user that
# made it it will add a view to the view counter
# and will render a template for viewing purposes
@app.route('/Corvus/Item/<int:item_id>/')
def ViewItem(item_id):
    userlogin = testlogin()
    try:
        item = session.query(CatalogItem).filter_by(id=item_id).one()
    except:
        return redirect(url_for('homepage'))
    usersitem = session.query(User).filter_by(id=item.user_id).one()
    if userlogin is not None:
        if userlogin.id == item.user_id:
            return render_template('Owner_item.html', item=item,
                                   userlogin=userlogin)
        else:
            views = item.View
            views = views + 1
            item.View = views
            return render_template('item.html', item=item, useritem=usersitem,
                                   userlogin=userlogin)
    else:
        return render_template('item.html', item=item, useritem=usersitem,
                               userlogin=userlogin)


# this page is used to display all items from
# a set catagory or all items it checks the uri for
# the catagory that the user wants to look
# at and if this catagory is all products it will render
# all items in the data base other wise it
# render all items within the catagory if an invalid
# catagory is entered it redirects the user to the homepage
@app.route('/Corvus/catagory/<string:catagory_Type>')
def ViewCatagory(catagory_Type):
    userlogin = testlogin()
    try:
        if catagory_Type == 'All products':
            Ctype = session.query(CatalogItem).all()
        else:
            Ctype = session.query(CatalogItem
                                  ).filter_by(catagory=catagory_Type).all()
        return render_template('catagory.html', items=Ctype,
                               catagory=catagory_Type,
                               userlogin=userlogin)
    except:
        return redirect(url_for('homepage'))


# this page lets the user edit there items it does
# this by taking the item from the uri and then
# checking if the user trying to access this page
# is the same user that made the item in the first
# place if this is the case it it will render the
# template unless the method is POST in which case it
# will take the new feilds and replace the old ones
@app.route('/Corvus/Item/<int:item_id>/Edit', methods=['GET', 'POST'])
def EditItem(item_id):
    userlogin = testlogin()
    edit_item = session.query(CatalogItem).filter_by(id=item_id).one()
    if userlogin is not None:
        if userlogin.id == edit_item.user_id:
            if request.method == 'POST':
                if (request.form['Name'] and
                        request.form['price'] and
                        request.form['description']):
                    edit_item.name = request.form['Name']
                    edit_item.price = request.form['price']
                    edit_item.catagory = request.form['catagory']
                    edit_item.description = request.form['description']
                    file = request.files['file']
                    if file.filename == '':
                        return render_template('Edit_item.html',
                                               item=edit_item,
                                               userlogin=userlogin)
                    if file and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'],
                                               filename))
                        edit_item.filename = filename
                        session.add(edit_item)
                        session.commit()
                        return redirect(url_for('ViewItem',
                                                item_id=edit_item.id))
                    else:
                        return render_template('Edit_item.html',
                                               item=edit_item,
                                               userlogin=userlogin)
                else:
                    return render_template('Edit_item.html', item=edit_item,
                                           userlogin=userlogin)
            else:
                return render_template('Edit_item.html', item=edit_item,
                                       userlogin=userlogin)
        else:
            return redirect(url_for('Login'))
    else:
        return redirect(url_for('Login'))


# this page is very much the same as the last page but
# instead of editing the item it is used for
# deleting the item instead
@app.route('/Corvus/Item/<int:item_id>/Del', methods=["GET", "POST"])
def DelItem(item_id):
    userlogin = testlogin()
    delete_item = session.query(CatalogItem).filter_by(id=item_id).one()
    if userlogin is not None:
        if userlogin.id == delete_item.user_id:
            if request.method == 'POST':
                session.delete(delete_item)
                session.commit()
                return redirect(url_for('homepage'))
            else:
                return render_template('Delete_item.html', item=delete_item,
                                       userlogin=userlogin)
        else:
            return redirect(url_for('Login'))
    else:
        return redirect(url_for('Login'))


# this page is used to display all items by the user that
# added them it does this by taking the
# user id from the uri and querying the data base for all
# items by this user if the user is not
# in the database it will redirect the user to the home page
# otherwise it renders the template
# display this infomation
@app.route('/Corvus/User/<int:User_id>')
def UsersUploads(User_id):
    userlogin = testlogin()
    try:
        items = session.query(CatalogItem).filter_by(user_id=User_id).all()
        user = session.query(User).filter_by(id=User_id).one()
        return render_template('Users_items.html', items=items, user=user,
                               userlogin=userlogin)
    except:
        return redirect(url_for('homepage'))


# this page is used to render a JSON version os a spacific item
# it does this by takeing the item ID
# from the uri and then serializing them into the json format
@app.route('/Corvus/Item/<int:item_id>/JSON')
def ItemJSON(item_id):
    try:
        item = session.query(CatalogItem).filter_by(id=item_id).one()
        return jsonify(items=item.serialize)
    except:
        return redirect(url_for('ItemsJSON'))


# this page much like the last serializies all the items
# from the database into a JSON format
@app.route('/Corvus/JSON')
def ItemsJSON():
    items = session.query(CatalogItem).all()
    return jsonify(items=[i.serialize for i in items])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

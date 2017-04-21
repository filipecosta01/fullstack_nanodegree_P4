from flask import Flask, render_template, url_for, request, redirect, flash, jsonify, session as login_session, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from catalog import Base, User, Category, Item
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

import random, string
import httplib2
import json
import requests

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/')
@app.route('/catalog')
def showCatalog():
    user_id = getUserIdFromSession(login_session)
    categories = session.query(Category).limit(12)
    latest_items = session.query(Item).order_by('created_at desc').limit(12)
    if user_id:
        user = user = session.query(User).filter_by(id=user_id).one()
        return render_template('catalog.html', user=user, categories=categories, latest_items=latest_items, side_navigation=True)
    return render_template('catalog.html', categories=categories, latest_items=latest_items, side_navigation=True)
@app.route('/login')
def showLogin():
    user_id = getUserIdFromSession(login_session)
    if user_id:
        flash('You are already logged in.', 'error')
        return redirect(url_for('showCatalog'))
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, CLIENT_URL=CLIENT_ID)

@app.route('/catalog/category/create', methods=['GET', 'POST'])
def createCategory():
    if request.method == 'POST':
        user_id = getUserIdFromSession(login_session)
        if not user_id:
            flash("Only authenticated users can create categories", 'error')
            return redirect(url_for('showCatalog'))
        category_name = request.form['title']
        if not category_name:
            flash("The new category needs a title", 'error')
            return render_template('create_category.html')
        category = Category(title=category_name, user_id=login_session['user_id'])
        session.add(category)
        session.commit()
        flash("The Category %s included with success!" %category.title, 'success')
        return redirect(url_for('showCatalog'))
    else:
        user_id = getUserIdFromSession(login_session)
        if not user_id:
            flash("Only authenticated users can create categories", 'error')
            return redirect(url_for('showCatalog'))
        return render_template('create_category.html')

@app.route('/catalog/category/<int:category_id>/edit', methods=['GET', 'POST'])
def editCategory(category_id):
    if request.method == 'POST':
        return render_template('catalog.html')
    else:
        return render_template('catalog.html')

@app.route('/catalog/category/<int:category_id>/items')
def showCategoryItems(category_id):
    return render_template('catalog.html', side_navigation=True)

@app.route('/catalog/category/<int:category_id>/item/<int:item_id>')
def showCategoryItem(category_id, item_id):
    return render_template('catalog.html', side_navigation=True)

@app.route('/catalog/category/<int:category_id>/item/create', methods=['GET', 'POST'])
def createItem(category_id):
    if request.method == 'POST':
        return render_template('catalog.html')
    else:
        return render_template('catalog.html')

@app.route('/catalog/category/<int:category_id>/item/<int:item_id>', methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    if request.method == 'POST':
        return render_template('catalog.html')
    else:
        return render_template('catalog.html')

@app.route('/catalog/category/<int:category_id>/item/<int:item_id>', methods=['GET', 'POST'])
def editItem(category_id, item_id):
    if request.method == 'POST':
        return render_template('catalog.html')
    else:
        return render_template('catalog.html')

def createUser(login_session):
    user_name = login_session['name']
    user_email = login_session['email']
    newUser = User(name=user_name, email=user_email)
    session.add(newUser)
    session.commit()

    user = session.query(User).filter_by(email=user_email).one()
    return user.id

@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state'), 401)
        response.headers['Content-type'] = 'application/json'
        return response

    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    google_id = credentials.id_token['sub']
    if result['user_id'] != google_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_google_id = login_session.get('google_id')
    if stored_credentials is not None and google_id == stored_google_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['google_id'] = google_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['name'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    isUserRegistrated = getUserId(login_session['email'])
    if isUserRegistrated:
        login_session['user_id'] = isUserRegistrated
        print "My user is already registrated: %s" %login_session['user_id']
    else:
        user = createUser(login_session)
        login_session['user_id'] = user
        print "My user was not registrated: %s" %login_session['user_id']

    output = 'Success!!!!!'
    flash("Welcome %s" % login_session['name'], 'success')

    return output

@app.route('/gdisconnect')
def doLogout():
    errorMessage = 'Failed to revoke the access token for the user...'
    try:
        access_token = login_session['access_token']
        if access_token is None:
            flash(errorMessage, 'error')
            return redirect(url_for('showCatalog'))
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        if result['status'] == '200':
            del login_session['user_id']
            del login_session['access_token']
            del login_session['google_id']
            del login_session['name']
            del login_session['email']
            flash('Successfuly logged out', 'success')
            return redirect(url_for('showCatalog'))
        else:
            flash(errorMessage, 'error')
            return redirect(url_for('showCatalog'))
    except:
        flash(errorMessage, 'error')
        return redirect(url_for('showCatalog'))

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserId(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

def getUserIdFromSession(login_session):
    try:
        user = login_session['user_id']
        return user
    except:
        return None

if __name__ == '__main__':
    app.secret_key = "full_stack_catalog_project"
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
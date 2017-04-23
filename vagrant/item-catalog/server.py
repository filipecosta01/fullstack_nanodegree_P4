from flask import Flask, render_template, url_for, request, redirect, flash, jsonify, session as login_session, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from catalog import Base, User, Category, Item
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

import random, string
import httplib2
import json
import requests

CLIENT_ID = json.loads(open('client_secrets.json', 'r')
                       .read())['web']['client_id']
app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/catalog/JSON')
def apiShowCatalog():
    '''
    Return the list of categories and latest items in json format.
    '''
    latest_items = session.query(Item).order_by('created_at desc').limit(12).all()
    categories = session.query(Category).limit(12).all()
    return jsonify(Category=[category.serialize for category in categories], LatestItems=[item.serialize for item in latest_items])

@app.route('/')
@app.route('/catalog')
def showCatalog():
    '''
    Show the main page with latest items registered on database.
    '''
    user_id = getUserIdFromSession(login_session)
    categories = session.query(Category).limit(12).all()
    latest_items = session.query(Item).order_by('created_at desc').limit(12).all()
    if user_id:
        user = user = session.query(User).filter_by(id=user_id).one()
        return render_template('catalog.html', user=user, categories=categories,
                               latest_items=latest_items, side_navigation=True)

    return render_template('catalog.html', categories=categories,
                           latest_items=latest_items, side_navigation=True)
@app.route('/login')
def showLogin():
    '''
    Show login view with google authentication only (for now...).
    '''
    user_id = getUserIdFromSession(login_session)
    if user_id:
        flash('You are already logged in.', 'error')
        return redirect(url_for('showCatalog'))
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state

    return render_template('login.html', STATE=state, CLIENT_URL=CLIENT_ID)

@app.route('/catalog/category/create', methods=['GET', 'POST'])
def createCategory():
    '''
    Render the form to create a new category and save it in database if all the
    information was filled correctly.
    '''
    user_id = getUserIdFromSession(login_session)
    if not user_id:
        flash('Only authenticated users can create categories', 'error')
        return redirect(url_for('showCatalog'))

    if request.method == 'POST':
        category_title = request.form['title']
        if not category_title:
            flash('New category needs a title', 'error')
            return render_template('create_category.html')
        category = Category(title=category_title,
                            user_id=login_session['user_id'])

        session.add(category)
        session.commit()

        flash('Category \'%s\' created with success!' %category.title, 'success')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('create_category.html')

@app.route('/catalog/category/<int:category_id>/edit', methods=['GET', 'POST'])
def editCategory(category_id):
    '''
    Render the form to edit a specific category and save it in database if all
    the information was filled correctly.
    '''
    user_id = getUserIdFromSession(login_session)
    if not user_id:
        flash('Only authenticated users can edit categories', 'error')
        return redirect(url_for('showCategoryItems',
                                category_id=category_id))
    category = session.query(Category).filter_by(id=category_id).one()
    if not category.user_id == user_id:
        flash('Only owner can edit a specific category', 'error')
        return redirect(url_for('showCategoryItems',
                                category_id=category_id))

    if request.method == 'POST':
        new_category_title = request.form['title']
        if not new_category_title:
            flash('Category needs a title', 'error')
            return render_template('edit_category.html', category=category)
        category.title = new_category_title
        session.commit()

        flash('Category \'%s\' edited with success!' %category.title, 'success')

        return redirect(url_for('showCategoryItems', category_id=category_id))
    else:
        return render_template('edit_category.html', category=category)

@app.route('/catalog/category/<int:category_id>/delete',
           methods=['GET', 'POST'])
def deleteCategory(category_id):
    '''
    Render the form to delete a specific category and delete it in database.
    '''
    user_id = getUserIdFromSession(login_session)
    if not user_id:
        flash('Only authenticated users can delete categories', 'error')
        return redirect(url_for('showCategoryItems',
                                category_id=category_id))

    category = session.query(Category).filter_by(id=category_id).one()
    if not category.user_id == user_id:
        flash('Only owner can delete a specific category', 'error')
        return redirect(url_for('showCategoryItems',
                                category_id=category_id))

    if request.method == 'POST':
        session.delete(category)
        session.commit()

        flash('Category \'%s\' deleted with success!' %category.title, 'success')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('delete_category.html', category=category)

@app.route('/catalog/category/<int:category_id>/items/JSON')
def apiShowCategoryItems(category_id):
    '''
    Return the list of items for a specific category in json format.
    '''
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id)
    category.items = [item.serialize for item in items]
    return jsonify(Category=category.serialize)

@app.route('/catalog/category/<int:category_id>/items')
def showCategoryItems(category_id):
    '''
    Render the items for a specific category selected.
    '''
    user_id = getUserIdFromSession(login_session)

    items = session.query(Item).filter_by(category_id=category_id).all()
    categories = session.query(Category).all()
    category = filter(lambda item: item.id == category_id, categories)[0]
    if user_id:
        user = user = session.query(User).filter_by(id=user_id).one()
        return render_template('category_items.html', user=user,
                               side_navigation=True, categories=categories,
                               items=items, category=category)

    return render_template('category_items.html', side_navigation=True,
                           categories=categories, items=items,
                           category=category)

@app.route('/catalog/category/<int:category_id>/item/<int:item_id>/JSON')
def apiShowCategoryItem(category_id, item_id):
    '''
    Return the item for a specific category in json format.
    '''
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    category.items = [item.serialize]
    return jsonify(Category=category.serialize)

@app.route('/catalog/category/<int:category_id>/item/<int:item_id>')
def showCategoryItem(category_id, item_id):
    '''
    Render one specific item for a specific category selected.
    '''
    user_id = getUserIdFromSession(login_session)

    categories = session.query(Category).all()
    category = filter(lambda item: item.id == category_id, categories)[0]
    item = session.query(Item).filter_by(id=item_id).one()
    if user_id:
        user = user = session.query(User).filter_by(id=user_id).one()
        return render_template('category_item.html', user=user,
                               categories=categories, item=item,
                               category=category, side_navigation=True)

    return render_template('category_item.html', categories=categories,
                           item=item, category=category, side_navigation=True,)

@app.route('/catalog/category/<int:category_id>/item/create',
           methods=['GET', 'POST'])
def createItem(category_id):
    '''
    Render the form to create a new item for a category and save it in
    database if all the information was filled correctly.
    '''
    user_id = getUserIdFromSession(login_session)

    if not user_id:
        flash('Only authenticated users can create items', 'error')
        return redirect(url_for('showCategoryItems',
                                category_id=category_id))

    categories = session.query(Category).all()
    category = filter(lambda item: item.id == category_id, categories)

    if request.method == 'POST':
        item_title = request.form['title']
        item_description = request.form['description']
        item_category = request.form['category']

        if not (item_title and item_description and item_category):
            flash('New item needs all the fields to be filled', 'error')
            return render_template('create_item.html',
                                   categories=categories,
                                   category=category[0],
                                   last_title=item_title,
                                   last_description=item_description,
                                   last_category=int(item_category))
        item = Item(title=item_title, description=item_description,
                    category_id=int(item_category),
                    user_id=login_session['user_id'])

        session.add(item)
        session.commit()

        flash('Item \'%s\' created with success!' %item.title, 'success')
        return redirect(url_for('showCategoryItems', category_id=category_id))
    else:
        return render_template('create_item.html', category=category[0],
                               categories=categories)

@app.route('/catalog/category/<int:category_id>/item/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    '''
    Render the form to delete a specific item and delete it in database.
    '''
    user_id = getUserIdFromSession(login_session)
    if not user_id:
        flash('Only authenticated users can access item edit form', 'error')
        return redirect(url_for('showCategoryItems',
                                category_id=category_id))

    item = session.query(Item).filter_by(id=item_id).one()
    if not item.user_id == user_id:
        flash('Only owner can delete a specific item', 'error')
        return redirect(url_for('showCategoryItem',
                                category_id=category_id, item_id=item_id))

    if request.method == 'POST':
        session.delete(item)
        session.commit()

        flash('Item \'%s\' deleted with success!' %item.title, 'success')
        return redirect(url_for('showCategoryItems', category_id=category_id))
    else:
        return render_template('delete_item.html', item=item)

@app.route('/catalog/category/<int:category_id>/item/<int:item_id>/edit', methods=['GET', 'POST'])
def editItem(category_id, item_id):
    '''
    Render the form to edit a specific item and save it in database if all
    the information was filled correctly.
    '''
    user_id = getUserIdFromSession(login_session)
    if not user_id:
        flash('Only authenticated users can access item edit form', 'error')
        return redirect(url_for('showCategoryItems',
                                category_id=category_id))

    categories = session.query(Category).all()
    item = session.query(Item).filter_by(id=item_id).one()

    if not item.user_id == user_id:
        flash('Only owner can edit a specific item', 'error')
        return redirect(url_for('showCategoryItem',
                                category_id=category_id, item_id=item_id))

    if request.method == 'POST':
        item_title = request.form['title']
        item_description = request.form['description']
        item_category = request.form['category']

        if not (item_title and item_description and item_category):
            flash('Edit item needs all the fields to be filled', 'error')
            return render_template('edit_item.html',
                                   categories=categories,
                                   item=item,
                                   last_title=item_title,
                                   last_description=item_description,
                                   last_category=int(item_category))

        item.title = item_title
        item.description = item_description
        item.category_id = int(item_category)

        session.commit()

        flash('Item \'%s\' edited with success!' %item.title, 'success')
        return redirect(url_for('showCategoryItem',
                                category_id=item.category_id, item_id=item_id))
    else:
        return render_template('edit_item.html', item=item, categories=categories)

def createUser(login_session):
    '''
    Create a new user using the login_session, with information returned from
    google oAuth.
    '''
    user_name = login_session['name']
    user_email = login_session['email']
    newUser = User(name=user_name, email=user_email)
    session.add(newUser)
    session.commit()

    user = session.query(User).filter_by(email=user_email).one()
    return user.id

@app.route('/gconnect', methods=['POST'])
def gconnect():
    '''
    Do the Google Authentication using oAuth and information from user's
    account. Creates a new session and store values like user_id and name.
    '''
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
    '''
    Revoke the Google Authentication using oAuth and information from user's
    account. Delete all the information from the session.
    '''
    errorMessage = 'Failed to revoke the access token for the user...'
    try:
        access_token = login_session['access_token']
        if access_token is None:
            flash(errorMessage, 'error')
            return redirect(url_for('showCatalog'))
        oAuthUrl = 'https://accounts.google.com/o/oauth2/revoke?token='
        url = '%s%s' % (oAuthUrl, access_token)
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        print result['status']
        print result
        if result['status'] == '200':
            del login_session['user_id']
            del login_session['access_token']
            del login_session['google_id']
            del login_session['name']
            del login_session['email']
            flash('Successfuly logged out', 'success')
            return redirect(url_for('showCatalog'))
        elif result['status'] == '400':
            del login_session['user_id']
            del login_session['access_token']
            del login_session['google_id']
            del login_session['name']
            del login_session['email']
            flash('Your token expired... Log In again', 'error')
            return redirect(url_for('showCatalog'))
        else:
            flash(errorMessage, 'error')
            return redirect(url_for('showCatalog'))
    except:
        flash(errorMessage, 'error')
        return redirect(url_for('showCatalog'))

def getUserInfo(user_id):
    '''
    Get the user information from database filtering by user_id in parameter.
    '''
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserId(email):
    '''
    Get the user_id information from database filtering by email in paramter.
    '''
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

def getUserIdFromSession(login_session):
    '''
    Get the user_id information from the session variable in parameter.
    '''
    try:
        user = login_session['user_id']
        return user
    except:
        return None

if __name__ == '__main__':
    app.secret_key = "full_stack_catalog_project"
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
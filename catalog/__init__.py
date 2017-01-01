from flask import Flask, render_template
from flask import request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from functools import wraps

from flask import session as login_session
import random
import string
# IMPORTS FOR THIS STEP
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catlog Application"

engine = create_engine('sqlite:///restaurantmenuauth.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
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
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
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
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
                            json.dumps('Current user is already connected'),
                            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    user_id = getUserID(login_session['email'])
    login_session['user_id'] = user_id

    if not user_id:
        user_id = createUser(login_session)
        login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius:\
                 150px;-webkit-border-radius:\
                 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            flash("Login required for access this url")
            return redirect(url_for('showItemss', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
    	response = make_response(json.dumps('Current \
                                            user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s'\
             % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully \
                                    disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash("Logout Successfully ")
        return redirect(url_for('showItemss'))
    else:
        response = make_response(json.dumps('Failed to \
                                        revoke token for given user', 400))
        response.headers['Content-Type'] = 'application/json'
        flash("Failed to logout ")
        return redirect(url_for('showItemss'))


@app.route('/')
def showItemss():
    # return "This page will show all home page"
    # items = session.query(Item).order_by(asc(Item.name))
        categories = session.query(Category).all()
        items = session.query(Item).all()
        if 'username' not in login_session:
            return render_template('publicindex.html',
                                   categories=categories, items=items)
        else:
            return render_template('index.html', categories=categories,
                                   items=items, user=login_session['username'])


@app.route('/addnewcat', methods=['GET', 'POST'])
@login_required
def newCat():
    # if 'username' not in login_session:
    #     return redirect('/')
    if request.method == 'POST':
        # print login_session['user_id']
        newCat = Category(name=request.form['name'],
                          url=request.form['url'],
                          user_id=login_session['user_id'])
        session.add(newCat)
        session.commit()
        return redirect(url_for('showItemss'))
    else:
        return render_template('addcat.html', user=login_session['username'])


@app.route('/catalog/<int:id>/items')
def showAllItemss(id):
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=id).one()
    creator = getUserInfo(category.user_id)
    items = session.query(Item).filter_by(
        category_id=id).all()
    if 'username' not in login_session:
        return render_template('publicitems.html',
                               items=items,
                               category=category,
                               categories=categories,
                               creator=creator)
    else:
        return render_template('items.html',
                               items=items,
                               category=category,
                               categories=categories,
                               user=login_session['username'],
                               creator=creator)
    # return "This page will show all home page"


# adding new item in catogery
@app.route('/catalog/<int:id>/newitem', methods=['GET', 'POST'])
@login_required
def addNewItem(id):
    category = session.query(Category).filter_by(id=id).one()
    if request.method == 'POST':
        print login_session['user_id']
        newItem = Item(name=request.form['name'],
                       img_url=request.form['img_url'],
                       description=request.form['description'],
                       category_id=id,
                       user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        return redirect(url_for('showAllItemss', id=id))
    else:
        return render_template('newitem.html',
                               user=login_session['username'],
                               category=category)
    # return "This page will show all home page"


# for view a specific item
@app.route('/catalog/<int:id>/<int:item_id>/viewitem')
def viewItem(id, item_id):
    category = session.query(Category).filter_by(id=id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    creator = getUserInfo(item.user_id)
    if 'username' not in login_session:
        return render_template('publicitem.html',
                               item=item,
                               category=category,
                               creator=creator)
    else:
        return render_template('item.html',
                               item=item,
                               category=category,
                               user=login_session['username'],
                               creator=creator)
    # return "This page will show all home page"


# delete item from list
@app.route('/catalog/<int:id>/<int:item_id>/deleteitem',
           methods=['GET', 'POST'])
@login_required
def deleteItem(id, item_id):
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    creator = getUserInfo(itemToDelete.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        flash("you are not allow to access this url")
        return redirect('/')
    else:
        if request.method == 'POST':
            session.delete(itemToDelete)
            session.commit()
            return redirect(url_for('showAllItemss', id=id))
        else:
            return render_template('deleteitem.html',
                                   user=login_session['username'])


#  edit item
@app.route('/catalog/<int:id>/<int:item_id>/edititem', methods=['GET', 'POST'])
@login_required
def editItem(id, item_id):
    editedItem = session.query(Item).filter_by(id=item_id).one()
    creator = getUserInfo(editedItem.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        flash("you are not allow to access this url")
        return redirect('/')
    else:
        if request.method == 'POST':
            editedItem.name = request.form['name']
            editedItem.description = request.form['description']
            editedItem.img_url = request.form['img_url']
            session.add(editedItem)
            session.commit()
            return redirect(url_for('viewItem',
                                    id=id,
                                    item_id=item_id))
        else:
            return render_template('edititem.html',
                                   user=login_session['username'],
                                   item=editedItem)


# api for displying json data for all categories
@app.route('/catalog.json')
def showItemssApi():
    categories = session.query(Category).all()
    return jsonify(catlogs=[c.serialize for c in categories])


# api for displying all items for a Category
@app.route('/catalog/<int:id>/items.json')
def viewItemsApi(id):
    category = session.query(Category).filter_by(id=id).one()
    items = session.query(Item).filter_by(
        category_id=id).all()    
    return jsonify(CategoryItems=[i.serialize for i in items])


# api for displying a specific item for a Category
@app.route('/catalog/<int:id>/<int:item_id>/viewitem.json')
def viewItemApi(id, item_id):
    category = session.query(Category).filter_by(id=id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

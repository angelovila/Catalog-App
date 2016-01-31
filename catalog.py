from flask import Flask, render_template, request, redirect, url_for
from flask import flash, jsonify, session as login_session, make_response
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Categories, Items, Users
import random
import requests
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.client import OAuth2Credentials
import httplib2
import json

from functools import wraps

app = Flask(__name__)

engine = create_engine('sqlite:///Catalogs.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(open(
    'client_secrets.json', 'r').read())['web']['client_id']


def login_required(f):
    """
    checks if user is logged in,
    if not, redirect user to /login

    used in create/edit/delete pages
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login')
def showlogin():
    """
    generate a random state token and
    store in login_session['state']

    used in gconnect() function
    """
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits) for x in range(32)
        )
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    uses Google login to protect data from unauthorized user

    pulls and stores some of user's Google info
    """

    # check if state token is valid
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        # store authorization code into credentials object
        oath_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oath_flow.redirect_uri = 'postmessage'
        credentials = oath_flow.step2_exchange(code)
        print 'printing of credentials: ', credentials
    except FlowExchangeError:
        response = make_response(
            json.dumps(
                'Failed to upgrade the authorization code.'), 401)
        response.header['Content-Type'] = 'application/json'
        return response

    # verify if access token is valid using google api server
    access_token = credentials.access_token
    print 'printing of access_token: ', access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # if there was an error in the access token info, abort
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 50)
        response.headers['Content-Type'] = 'application/json'

    # verify that access token is used for intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps(
                "Token's user ID doesn't match given user ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps(
                "Token's client ID does not match app's"), 401)
        print "Token's clientID does not match app's"
        response.headers['Content-Type'] = 'application/json'
        return response

    # check to see if user is already logged in to the system
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_d:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Types'] = 'application/json'

    # store the access token in the session for later use
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # get user info using google+ api
    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)  # use to_json?

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # check if user is already in Users table, if not, create

    user_id = getUserID(login_session['email'])
    if not user_id:
        # calls createUser function to store user info in database
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    flash("you are now logged in as %s" % login_session['username'])

    return output


@app.route("/gdisconnect")
def gdisconnect():
    """
    signs user out

    deletes user credentials pulled/generated from gconnect()
    """
    # check if user is connected
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps('Current user is not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    # google's url to revoke tokens
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token

    h = httplib2.Http()
    # this is to store google's response after revoke
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':  # successfully disconnected
        # reset the user's session
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        # del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type']
        # response that a user has logged out the application
        return response

    else:
        # for whatever reason the given token was invalid
        response = make_response(json.dumps(
            'failed to revoke token for given user'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/')
def latest_items():
    """
    renders homepage while passing categories and latest items
    """
    categories = session.query(Categories).all()
    # display only the last 10 items added (regardless of what category)
    items = session.query(Items).order_by(Items.dateadded.desc()).limit(10)
    return render_template('latestitems.html',
                           categories=categories, items=items)


@app.route('/catalog/<category_name>/<int:category_id>/')
def category_page(category_name, category_id):
    """
    renders category page while passing category information and
    all items in the specified category
    """
    items = session.query(Items).filter_by(categoryID=category_id)
    category = session.query(Categories).filter_by(id=category_id).one()
    return render_template('categorypage.html', items=items,
                           category=category, login_session=login_session)


@app.route('/catalog/<category_name>/<int:category_id>/JSON/')
def category_page_JSON(category_name, category_id):
    """
    returns category information and all items
    in the specified category in JSON format
    """
    items = session.query(Items).filter_by(categoryID=category_id).all()
    category = session.query(Categories).filter_by(id=category_id).one()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<product_category_id>/<product_name>/<int:product_id>/')
def product_page(product_category_id, product_name, product_id):
    """
    renders product page while passing item
    information of specified category
    """
    item = session.query(Items).filter_by(id=product_id).one()
    return render_template('productpage.html', item=item,
                           login_session=login_session)


@app.route(
    '/catalog/<product_category_id>/<product_name>/<int:product_id>/JSON/')
def product_page_JSON(product_category_id, product_name, product_id):
    """
    returns specified product in JSON format
    """
    item = session.query(Items).filter_by(id=product_id).one()
    return jsonify(item=item.serialize)


def createUser(login_session):
    """
    stores user information in database

    used in gconnect()
    """
    newUser = Users(name=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(Users).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """
    returns user information of specified user_id
    """
    user = session.query(Users).filter_by(id=user.id)
    return user


def getUserID(email):
    """
    returns user.id of specified email
    """
    try:
        user = session.query(Users).filter_by(email=email).one()
        return user.id
    except:
        print "email doesn't exist in database - getUserID function"
        return None


@app.route('/catalog/create-product/', methods=['GET', 'POST'])
@login_required
def create_product_page():
    """
    renders create product page

    saves product information entered in the page to database
    """
    categories = session.query(Categories)
    if request.method == 'GET':
        return render_template('newproduct.html', categories=categories)

    if request.method == 'POST':
        item = Items(name=request.form['name'],
                     description=request.form['description'],
                     categoryID=request.form['category'],
                     user_id=login_session['user_id'],
                     image=request.form['image'])
        session.add(item)
        session.commit()
        message = 'successfully created product'
        flash(message)
        return redirect(url_for('latest_items'))


@app.route('/catalog/create-category/', methods=['GET', 'POST'])
@login_required
def create_category_page():
    """
    renders create category page

    saves category information entered in the page to database
    """
    if request.method == 'GET':
        return render_template('newcategory.html')

    if request.method == 'POST':
        category = Categories(name=request.form['name'],
                              user_id=login_session['user_id'])
        session.add(category)
        session.commit()
        message = 'successfully created category'
        flash(message)
        return redirect(url_for('latest_items'))


@app.route('/catalog/<category_name>/<int:category_id>/edit',
           methods=['GET', 'POST'])
@login_required
def edit_category_page(category_name, category_id):
    """
    renders edit category page

    updates category information entered in the page to database
    """
    category = session.query(Categories).filter_by(id=category_id).one()

    # check if current user is the one who created the category
    if category.user_id == login_session['user_id']:

        if request.method == 'GET':
            return render_template('editcategory.html', category=category)
        if request.method == 'POST':
            if request.form['name']:
                category.name = request.form['name']
                session.add(category)
                session.commit()
                message = 'successfully updated category name'
                flash(message)
                return redirect(url_for('category_page',
                                        category_name=category.name,
                                        category_id=category.id))

    else:
        output = 'User is not authorized to edit the category'
        return output


@app.route('/catalog/<category_name>/<int:category_id>/delete',
           methods=['GET', 'POST'])
@login_required
def delete_category_page(category_name, category_id):
    """
    renders delete category page

    delete specified category out of database
    """
    category = session.query(Categories).filter_by(id=category_id).one()
    # check if user is the one who created the category
    if category.user_id == login_session['user_id']:
        if request.method == 'GET':
            return render_template('deletecategory.html', category=category)

        if request.method == 'POST':
            session.delete(category)
            session.commit()
            return redirect(url_for('latest_items'))
    else:
        output = 'User is not authorized to delete category'
        return output


@app.route(
    '/catalog/<product_category_id>/<product_name>/<int:product_id>/delete',
    methods=['GET', 'POST'])
@login_required
def delete_product_page(product_category_id, product_name, product_id):
    """
    renders delete category page

    delete specified category out of database
    """
    item = session.query(Items).filter_by(id=product_id).one()
    if item.user_id == login_session['user_id']:

        if request.method == 'GET':
            return render_template('deleteproduct.html', item=item)
        if request.method == 'POST':
            session.delete(item)
            session.commit()
            return redirect(url_for('latest_items'))
    else:
        output = 'User is not authorized to delete product'


@app.route(
    '/catalog/<product_category_id>/<product_name>/<int:product_id>/edit',
    methods=['GET', 'POST'])
@login_required
def edit_product_page(product_category_id, product_name, product_id):
    """
    renders edit product page

    update product using information entered in the page
    """
    item = session.query(Items).filter_by(id=product_id).one()
    if item.user_id == login_session['user_id']:
        if request.method == 'GET':
            return render_template('editpage.html', item=item)
        if request.method == 'POST':
            if request.form['name']:
                item.name = request.form['name']
            if request.form['description']:
                item.description = request.form['description']
            session.add(item)
            session.commit()
            message = "successfully updated product"
            flash(message)
            # edit_product(product_id,#enter form values and names)
            # return url_for()
            return redirect(url_for('product_page',
                                    product_category_id=product_category_id,
                                    product_name=product_name,
                                    product_id=item.id))
    else:
        output = "User is not authorized to edit product"
        return output


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)

    '''
    /restaurant/1/new/
    /restaurant/1/2/edit/
    /restaurant/1/2/delete/
    '''

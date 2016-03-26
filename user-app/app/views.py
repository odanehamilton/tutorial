"""
Flask Documentation:     http://flask.pocoo.org/docs/
Jinja2 Documentation:    http://jinja.pocoo.org/2/documentation/
Werkzeug Documentation:  http://werkzeug.pocoo.org/documentation/

This file creates your application.
"""

from app import app
from flask import render_template, request, redirect, url_for,jsonify,g,session
from app import db

from flask.ext.wtf import Form 
from wtforms.fields import TextField # other fields include PasswordField 
from wtforms.validators import Required, Email
from app.models import Myprofile
from app.forms import LoginForm

from flask.ext.login import login_user, logout_user, current_user, login_required
from app import app, db, lm, oid
from app import oid, lm

class ProfileForm(Form):
     id_num = TextField('ID')
     first_name = TextField('First Name', validators=[Required()])
     last_name = TextField('Last Name', validators=[Required()])
     username = TextField('Username', validators=[Required()])
     password = TextField('Password', validators=[Required()])
     # evil, don't do this
   # image = TextField('Image', validators=[Required(), Email()])


@app.before_request
def before_request():
    g.user = current_user
    
@lm.user_loader
def load_user(id):
    return Myprofile.query.get(int(id))
    
    
@oid.after_login
def after_login(resp):
    if resp.email is None or resp.email == "":
        flash('Invalid login. Please try again.')
        return redirect(url_for('login'))
    user = MyProfile.query.filter_by(email=resp.email).first()
    if user is None:
        nickname = resp.nickname
        if nickname is None or nickname == "":
            nickname = resp.email.split('@')[0]
        user = MyProfile(nickname=nickname, email=resp.email)
        db.session.add(user)
        db.session.commit()
    remember_me = False
    if 'remember_me' in session:
        remember_me = session['remember_me']
        session.pop('remember_me', None)
    login_user(user, remember = remember_me)
    return redirect(request.args.get('next') or url_for('index'))
    
###
# Routing for your application.
###
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    usernames = Myprofile.query.all()
    if request.method == 'POST':
        for names in usernames:
            if request.form['username'] == names.username and request.form['password'] == names.password:
                session['logged_in'] = True
                return redirect(url_for('profile_view', id_num=names.id_num))
        else:
            error = "Invalid login data"
    return render_template('login.html', error=error)
    
    
@app.route('/logout')
def logout():
    """Render website's logout page."""
    session.pop('logged_in', None)
    return redirect(url_for('home'))

    
    
    #if g.user is not None and g.user.is_authenticated:
     #   return redirect(url_for('index'))
    #form = LoginForm()
   # if form.validate_on_submit():
  #      session['remember_me'] = form.remember_me.data
 #       return oid.try_login(form.openid.data, ask_for=['nickname', 'email'])
#    return render_template('login.html', 
     #                      title='Sign In',
    #                       form=form,
   #                        providers=app.config['OPENID_PROVIDERS'])

@app.route('/')
def home():
    """Render website's home page."""
    return render_template('home.html')

@app.route('/profile/', methods=['POST','GET'])
def profile_add():
    db.create_all()
    if request.method == 'POST':
        id_num = request.form['id_num']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        password = request.form['password']

        # write the information to the database
        newprofile = Myprofile(id_num = id_num, first_name=first_name,
                               last_name=last_name, username=username, password=password)
        db.session.add(newprofile)
        db.session.commit()

        return "{} {} was added to the database".format(request.form['first_name'],
                                             request.form['last_name']) + render_template('home.html')
        

    form = ProfileForm()
    return render_template('profile_add.html',
                           form=form)
                           
                           

@app.route('/profiles/',methods=["POST","GET"])
def profile_list():
    profiles = Myprofile.query.all()
    
    return render_template('profile_list.html',
                            profiles=profiles)

@app.route('/profile/<int:id_num>')
def profile_view(id_num):
    profile = Myprofile.query.get(id_num)
    return render_template('profile_view.html',profile=profile)


@app.route('/about/')
def about():
    """Render the website's about page."""
    return render_template('about.html')


###
# The functions below should be applicable to all Flask apps.
###

@app.route('/<file_name>.txt')
def send_text_file(file_name):
    """Send your static text file."""
    file_dot_text = file_name + '.txt'
    return app.send_static_file(file_dot_text)


@app.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=600'
    return response


@app.errorhandler(404)
def page_not_found(error):
    """Custom 404 page."""
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0",port="8888")

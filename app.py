from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Secret
from forms import UserForm, RegisterForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///login_demo"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)

toolbar = DebugToolbarExtension(app)


@app.route('/')
def home_page():
    return render_template('index.html')


@app.route('/secrets', methods=['GET', 'POST'])
def show_secrets():
    if "user_id" not in session:
        flash("Please login first!", "danger")
        return redirect('/')
    form = SecretForm()
    all_secrets = Secrets.query.all()
    if form.validate_on_submit():
        text = form.text.data
        new_secret = Secret(text=text, user_id=session['user_id'])
        db.session.add(new_secret)
        db.session.commit()
        flash('Secret Created!', 'success')
        return redirect('/secrets')

    return render_template("secrets.html", form=form, secrets=all_secrets)


@app.route('/secrets/<int:id>', methods=["POST"])
def delete_secrets(id):
    """Delete Secret"""
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/login')
    secret = Secret.query.get_or_404(id)
    if secret.user_id == session['user_id']:
        db.session.delete(secret)
        db.session.commit()
        flash("Secret deleted!", "info")
        return redirect('/secret')
    flash("You don't have permission to do that!", "danger")
    return redirect('/secrets')


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        new_user = User.register(username, password)
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username taken.  Please pick another')
            return render_template('register.html', form=form)
        session['user_id'] = new_user.id
        flash('Welcome! Successfully Created Your Account!', "success")
        return redirect('/secrets')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            flash(f"Welcome Back, {user.username}!", "primary")
            session['user_id'] = user.id
            return redirect('/secrets')
        else:
            form.username.errors = ['Invalid username/password.']

    return render_template('login.html', form=form)


@app.route('/logout')
def logout_user():
    session.pop('user_id')
    flash("Goodbye!", "info")
    return redirect('/')

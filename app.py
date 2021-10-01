from flask import Flask, render_template, url_for, request, redirect, session, g, flash
from flask_mysqldb import MySQL
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length
from functools import wraps
from passlib.hash import sha256_crypt
import os
SECRET_KEY = os.urandom(32)


app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'todoapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['SECRET_KEY'] = SECRET_KEY
 
mysql = MySQL(app)


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators = [DataRequired(), Length(min=2, max=25)])
    password = PasswordField('Password', validators = [DataRequired(), EqualTo('confirm', message='Passwords must match'), Length(min=6, max=25)])
    confirm = PasswordField('Confirm password')

class LoginForm(FlaskForm):
    username = StringField('Username', validators = [DataRequired(), Length(min=2, max=25)])
    password = PasswordField('Password', validators = [DataRequired(), Length(min=6, max=25)])

class NewTodoForm(FlaskForm):
    content = TextAreaField('', validators = [DataRequired(), Length(max=200)])

@app.route("/", methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data 
        password = form.password.data
        cursor = mysql.connection.cursor()
        query_user = 'SELECT * FROM users WHERE username=%s'
        result = cursor.execute(query_user, (username,))
        cursor.close()
        if result == 0:
            username = form.username.data 
            password = sha256_crypt.encrypt(form.password.data)
            cursor = mysql.connection.cursor()
            query = 'INSERT INTO users(username, password) VALUES (%s, %s)'
            cursor.execute(query, (username, password))
            mysql.connection.commit()
            cursor.close()
            flash('You registered successfully.', 'success')
            return redirect(url_for("login"))
        else:
            flash('This username is taken.', 'danger')
            return redirect(url_for("register"))
    else:
        return render_template('register.html', form=form)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("You need to login first.",'danger')
            return redirect(url_for("login"))
    return decorated_function

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data 
        password_entered = form.password.data 
        cursor = mysql.connection.cursor()
        query = 'SELECT * FROM users WHERE username=%s'
        result = cursor.execute(query,(username,))
        if result > 0:
            user = cursor.fetchone()
            if sha256_crypt.verify(password_entered, user["password"]):
                session["logged_in"] = True 
                session["username"] = user["username"]
                flash('You logged in successfully.', 'success')
                return redirect(url_for("index"))
            else:
                flash('The password you entered for this username is not valid.', 'danger')
                return redirect(url_for("login"))
        else:
            flash('No user exists with this username.', 'danger')
            return redirect(url_for("login"))
    else:
        return render_template('login.html', form=form)

@app.route("/home")
@login_required
def index():
    cursor = mysql.connection.cursor()
    query = 'SELECT * FROM todos WHERE user=%s'
    result = cursor.execute(query, (session["username"],))
    todos = cursor.fetchall()
    return render_template('index.html', result=result, todos=todos)

@app.route("/newtodo", methods=["GET", "POST"])
@login_required
def newtodo():
    form = NewTodoForm(request.form)
    if request.method == "POST" and form.validate_on_submit():
        content = form.content.data 
        cursor = mysql.connection.cursor() 
        query = 'INSERT INTO todos(content, user) VALUES(%s, %s)'
        cursor.execute(query,(content, session["username"]))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for("index"))
    else:
        return render_template('newtodo.html', form=form)

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You logged out successfully.", "danger")
    return redirect("/")

@app.route("/cancel")
@login_required
def cancel():
    return redirect(url_for("index"))

@app.route("/delete/<string:id>")
@login_required
def delete(id):
    cursor = mysql.connection.cursor()
    query = 'SELECT * FROM todos WHERE id=%s AND user=%s'
    result = cursor.execute(query,(id, session["username"]))
    cursor.close()
    if result > 0:
        cursor = mysql.connection.cursor()
        query_delete = 'DELETE FROM todos WHERE id=%s'
        cursor.execute(query_delete, (id,))
        mysql.connection.commit()
        cursor.close()
        flash('To-do deleted successfully.', 'success')
        return redirect(url_for("index"))
    else:
        flash('Something went wrong.', 'danger')
        return redirect(url_for("index"))

@app.route("/edit/<string:id>", methods=['GET', 'POST'])
@login_required
def edit(id):
    form = NewTodoForm(request.form)
    cursor = mysql.connection.cursor()
    query = 'SELECT * FROM todos WHERE id=%s AND user=%s'
    result = cursor.execute(query,(id, session["username"]))
    todo = cursor.fetchone()
    if result > 0:
        if request.method == "POST" and form.validate_on_submit():
            query_update = 'UPDATE todos SET content=%s WHERE id=%s'
            cursor.execute(query_update,(form.content.data, id))
            mysql.connection.commit()
            flash('To-do updated successfully', 'success')
            return redirect(url_for("index"))
        else:
            form.content.data = todo["content"]
            return render_template('edit.html', form=form)
    else:
        flash('Something went wrong.', 'danger')
        return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
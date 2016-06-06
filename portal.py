#!/usr/bin/env python

from flask import Flask, request, session, abort, render_template, redirect
from oath import accept_hotp
import json

app = Flask(__name__)
app.secret_key = 'L\xe6\x1f\xfd|\xde\xa4\xbf\xbd\xf2\x03\xf5\xd1\x9a\xde\xa7\xad\xeeh\x9e\xa9\x86\xbe\x97'


def valid_login():
    try:
        credentials = app.auth[request.form['username']]
    except KeyError:
        return False

    if request.form['password'] != credentials['password']:
        return False

    # Check oath-hotp credentals
    (valid, counter) = accept_hotp(credentials['shared_secret'], request.form['oath'], int(credentials['shared_counter']), format='dec8', drift=128)
    if not valid:
        return False

    # Save the new counter
    credentials['shared_counter'] = counter
    with open('auth.json', 'w') as auth_file:
        json.dump(app.auth, auth_file)

    return True


@app.route("/auth")
def auth():
    if 'username' in session:
        return "logged"
    else:
        abort(401)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if valid_login():
            session['username'] = request.form['username']
            
            referee = request.args.get('from', '')
            if referee != '':
                return redirect(referee)

            return "login ok"

        else:
            abort(403)

    else:
        return render_template('login.html')


@app.route("/logout")
def logout():
    if 'username' in session:
        session.pop('username', None)
    return "logout"


if __name__ == "__main__":
    with open('auth.json') as auth_file:
        app.auth = json.load(auth_file)

    app.run()

import os
import re

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///bestclinic.db")


SPECIALISTS = [
    "allergist",
    "gastroenterologist",
    "hematologist",
    "hepatologist",
    "gynecologist",
    "dermatologist",
    "endocrinologist",
    "cardiologist",
    "mammologist",
    "neurologist",
    "neurosurgeon",
    "oncogynecologist",
    "oncologist",
    "orthopedist",
    "otolaryngologist",
    "ophthalmologist",
    "proctologist",
    "psychiatrist",
    "psychotherapist",
    "pulmonologist",
    "rehabilitator",
    "rheumatologist",
    "traumatologist",
    "urologist",
    "urooncologist",
    "physiotherapist",
    "phlebologist",
    "surgeon"
]


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return render_template("staffonly.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password is strong
        elif len(request.form.get("password")) < 8:
            return apology("password is too short", 400)

        elif re.search(r"\d", request.form.get("password")) == None:
            return apology("password must contain numbers", 400)

        elif re.search(r"[a-zA-Z]", request.form.get("password")) == None:
            return apology("password must contain letters", 400)

        # Ensure confirm password was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure confirm password = password
        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("passwords don't match", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username doesn't exist
        if len(rows) != 0:
            return apology("the username was already taken", 400)

        # Validate submission & hashing the password
        username = request.form.get("username")
        password = request.form.get("password")
        hash = generate_password_hash(password)

        # Remember registrant
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)

        # Remember which user has logged in
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return render_template("staffonly.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/services")
def services():
    return render_template("services.html")


@app.route("/price")
def price():
    return render_template("price.html")


@app.route("/contacts")
def contacts():
    return render_template("contacts.html")


@app.route("/appointments")
def appointments():
    return render_template("appointments.html")


@app.route("/staffonly")
@login_required
def staffonly():
    return render_template("staffonly.html")


@app.route("/reviews", methods=["GET", "POST"])
def reviews():

    if request.method == "POST":

        username = request.form.get("username")
        specialist = request.form.get("specialist")
        userreview = request.form.get("userreview")
        recommend = request.form.get("recommend")
        try:
            grade = int(request.form.get("grade"))
        except:
            return apology("Grade must be an integer!", 400)

        if not username:
            return apology("Please, enter a username", 400)

        if not userreview:
            return apology("Please, enter a review", 400)

        db.execute("INSERT INTO reviews (username, specialist, userreview, grade, recommend) VALUES (?, ?, ?, ?, ?)",
                    username, specialist, userreview, grade, recommend)

        return redirect("/")

    else:
        reviews = db.execute("SELECT username, date, specialist, userreview, grade, recommend FROM reviews GROUP BY date")
        for review in reviews:
            if review["recommend"] == "on":
                review["recommend"] = "Recommend"
            else:
                review["recommend"] = "Not recommend"
        return render_template("reviews.html", reviews=reviews, specialists=SPECIALISTS)


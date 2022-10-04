import os
from cs50 import SQL
from flask import Flask, redirect, render_template, session, request
from werkzeug.security import check_password_hash, generate_password_hash
from flask_session import Session
from functools import wraps
from datetime import date

# configure application
app = Flask(__name__)

# ensure templates are auto_reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# configure cs50 library to use SQLite database
db = SQL("sqlite:///data.db")

# access only with login
def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

# apology
def apology(message, code=400):
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", bottom=escape(message))

# register user
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username doesn't exist
        if len(rows) != 0:
            return apology("username already exists", 400)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirnation password was submitted
        if not request.form.get("confirmation"):
            return apology("must provide password again", 400)

        # Ensure passwords match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Add new user to database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", request.form.get("username"),
                   generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8))

        # Remember which user has logged in
        session["user_id"] = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))[0]["id"]

        # Add default sites
        db.execute("INSERT INTO sites (name, url) SELECT name, url FROM default_sites")

        # Change NULL id to user's id
        db.execute("UPDATE sites SET id = ? WHERE id IS NULL", session["user_id"])

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("register.html")


# login page
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

# user's games
@app.route("/")
@login_required
def mygames():
    # Show games
    games = db.execute("SELECT * FROM games WHERE id = ?", session["user_id"])
    return render_template("mygames.html", games=games)

# add a game
@app.route("/add", methods=["POST"])
@login_required
def add():
    if request.form.get("date"):
        day = request.form.get("date")
    else:
        day = date.today()
    if request.form.get("price"):
        price = request.form.get("price")
    else:
        price = None
    # Insert game into database
    db.execute("INSERT INTO games (id, name, review, photo, bought_played, rating, price, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                session["user_id"], request.form.get("name"), request.form.get("review"), request.form.get("photo"),
                request.form.get("bought_played"), request.form.get("rating"), price, day)
    # Redirect user to list of his games
    return redirect("/")

# sort games
@app.route("/sort", methods=["POST"])
@login_required
def sort():
    if request.form.get('sort_option_buy'):
        execution = f"SELECT * FROM games WHERE id = ? and bought_played = ?"
        games = db.execute(f"{execution}", session["user_id"], request.form.get('sort_option_buy'))
        sorted_names = {
            "yes" : "Own it",
            "no" : "Don't own it",
        }
        return render_template("mygames.html", games=games, sort_name = sorted_names[request.form.get('sort_option_buy')], owning="yes")
    else:
        execution = f"SELECT * FROM games WHERE id = ? ORDER BY {request.form.get('sort_option')}"
        games = db.execute(f"{execution}", session["user_id"])
        # for sorted by button
        sorted_names = {
            "lower(name) ASC" : "name, A-Z",
            "lower(name) DESC" : "name, Z-A",
            "rating ASC" : "rating, 0-10",
            "rating DESC" : "rating, 10-0",
            "date ASC" : "date, old to new",
            "date DESC" : "date, new to old",
            "price ASC" : "price, small to big",
            "price DESC" : "price, big to small",
        }
        return render_template("mygames.html", games=games, sort_name = sorted_names[request.form.get('sort_option')])

# delete a game
@app.route("/delete", methods=["POST"])
def delete():
    game_id = request.form.get("game_id")
    db.execute("DELETE FROM games WHERE id = ? AND game_id = ?", session["user_id"], game_id)
    return redirect("/")

# choose first player
@app.route("/random")
def random():
        return render_template("random.html")

# search more games
@app.route("/searchgames", methods=["GET", "POST"])
def search():
    sites = db.execute("SELECT * FROM sites WHERE id = ?", session["user_id"])
    return render_template("searchgames.html", sites=sites)

# add a site
@app.route("/add_site", methods=["POST"])
@login_required
def add_site():
        # Insert game into database
        db.execute("INSERT INTO sites (id, name, url) VALUES (?, ?, ?)",
                    session["user_id"], request.form.get("name"), request.form.get("url"))
        # Redirect user to list of his games
        return redirect("/searchgames")

# delete a site
@app.route("/delete_site", methods=["POST"])
def delete_site():
    site_id = request.form.get("site_id")
    db.execute("DELETE FROM sites WHERE id = ? AND site_id = ?", session["user_id"], site_id)
    return redirect("/searchgames")

# log user out
@app.route("/logout")
def logout():
    # Forget any user_id
    session.clear()
    # Redirect user to login form
    return redirect("/")

from flask import Flask, request, jsonify, render_template, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Home page
@app.route("/")
def index():
    return render_template("index.html", message="Welcome to Flask!")

# Route with request parameters
@app.route("/greet", methods=["GET", "POST"])
def greet():
    if request.method == "POST":
        name = request.form.get("name", "Guest")
    else:
        name = request.args.get("name", "Guest")
    return jsonify({"message": f"Hello, {name}!"})

# Simple JSON response
@app.route("/api/data")
def api_data():
    return jsonify({"status": "success", "data": [1, 2, 3, 4, 5]})

# Redirect example
@app.route("/redirect")
def redirect_example():
    return redirect(url_for("index"))

# Setting and getting session data
@app.route("/set_session")
def set_session():
    session['username'] = "flask_user"
    return "Session set!"

@app.route("/get_session")
def get_session():
    username = session.get("username", "Not set")
    return f"Session username: {username}"

# Form handling
@app.route("/form", methods=["GET", "POST"])
def form_example():
    if request.method == "POST":
        data = request.form.to_dict()
        return jsonify(data)
    return render_template("form.html")

# Path parameter
@app.route("/user/<username>")
def user_profile(username):
    return f"User Profile: {username}"

# Query parameters
@app.route("/search")
def search():
    query = request.args.get("q", "No query provided")
    return f"Search results for: {query}"

# Custom error handling
@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"error": "Page not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=True)

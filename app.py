from flask import Flask, render_template, request, redirect, url_for, session, Response
from database import init_db, register_user, validate_user

app = Flask(__name__)
app.secret_key = "shieldx_operation_workspace_secure_key"

init_db()

@app.route("/", methods=["GET", "POST"])
def home():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", username=session["user"])

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if validate_user(username, password):
            session["user"] = username
            return redirect(url_for("home"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    msg = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if register_user(username, password):
            msg = "Registration successful! Please login."
        else:
            msg = "Username already exists."
    return render_template("register.html", msg=msg)

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

@app.route("/stream_scan")
def stream_scan():
    if "user" not in session:
        return "Unauthorized", 401
    url = request.args.get("url")
    if not url:
        return "Missing URL", 400
        
    # Fixed parameter extraction names to match JavaScript
    target_username = request.args.get("username", "")
    target_password = request.args.get("password", "")
        
    from scanner import scan_website_stream
    
    return Response(
        scan_website_stream(url, username=target_username, password=target_password), 
        mimetype="text/event-stream"
    )

if __name__ == "__main__":
    app.run(debug=True)
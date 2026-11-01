from functools import wraps
from typing import Callable, TypeVar

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from db import execute, fetch_one

ViewFunction = TypeVar("ViewFunction", bound=Callable[..., object])


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    @app.context_processor
    def inject_current_user() -> dict[str, object]:
        return {"current_user": session.get("username")}

    def login_required(view: ViewFunction) -> ViewFunction:
        @wraps(view)
        def wrapped_view(*args: object, **kwargs: object) -> object:
            if "user_id" not in session:
                flash("Please log in to continue.", "error")
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)

        return wrapped_view  # type: ignore[return-value]

    def role_required(*allowed_roles: str) -> Callable[[ViewFunction], ViewFunction]:
        def decorator(view: ViewFunction) -> ViewFunction:
            @wraps(view)
            def wrapped_view(*args: object, **kwargs: object) -> object:
                if "user_id" not in session:
                    flash("Please log in to continue.", "error")
                    return redirect(url_for("login", next=request.path))
                if session.get("role") not in allowed_roles:
                    return "Forbidden", 403
                return view(*args, **kwargs)

            return wrapped_view  # type: ignore[return-value]

        return decorator

    @app.get("/")
    def hello() -> str:
        return render_template("hello.html")

    @app.route("/register", methods=["GET", "POST"])
    def register() -> str:
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            if not username or not email or len(password) < 8:
                flash("Username, email, and a password of at least 8 characters are required.", "error")
                return render_template("register.html"), 400

            if fetch_one("SELECT id FROM users WHERE email = %s", (email,)):
                flash("An account with that email already exists.", "error")
                return render_template("register.html"), 409

            execute(
                """
                INSERT INTO users (username, email, password_hash, role)
                VALUES (%s, %s, %s, 'user')
                """,
                (username, email, generate_password_hash(password)),
            )
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login() -> str:
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = fetch_one(
                "SELECT id, username, password_hash, role FROM users WHERE email = %s",
                (email,),
            )

            if user is None or not check_password_hash(str(user["password_hash"]), password):
                app.logger.warning("Failed login for email=%s", email)
                flash("Invalid email or password.", "error")
                return render_template("login.html"), 401

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            next_url = request.args.get("next")
            return redirect(next_url if next_url and next_url.startswith("/") else url_for("hello"))

        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout() -> object:
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("hello"))

    @app.get("/agent")
    @role_required("agent", "admin")
    def agent_home() -> str:
        return "Agent area"

    @app.get("/admin")
    @role_required("admin")
    def admin_home() -> str:
        return "Admin area"

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

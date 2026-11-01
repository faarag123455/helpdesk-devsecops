from functools import wraps
from typing import Callable, TypeVar

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from db import execute, execute_returning, fetch_all, fetch_one

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

    def can_manage_ticket(ticket: dict[str, object]) -> bool:
        return session.get("role") in {"agent", "admin"} or ticket["created_by"] == session["user_id"]

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

    @app.get("/tickets")
    @login_required
    def tickets() -> str:
        if session.get("role") in {"agent", "admin"}:
            ticket_rows = fetch_all(
                """
                SELECT t.id, t.title, t.status, t.priority, t.created_at,
                       u.username AS creator, a.username AS assignee
                FROM tickets t
                JOIN users u ON u.id = t.created_by
                LEFT JOIN users a ON a.id = t.assigned_to
                ORDER BY t.created_at DESC
                """
            )
        else:
            ticket_rows = fetch_all(
                """
                SELECT t.id, t.title, t.status, t.priority, t.created_at,
                       u.username AS creator, a.username AS assignee
                FROM tickets t
                JOIN users u ON u.id = t.created_by
                LEFT JOIN users a ON a.id = t.assigned_to
                WHERE t.created_by = %s
                ORDER BY t.created_at DESC
                """,
                (session["user_id"],),
            )
        return render_template("tickets.html", tickets=ticket_rows)

    @app.route("/tickets/new", methods=["GET", "POST"])
    @login_required
    def new_ticket() -> str:
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            priority = request.form.get("priority", "medium")
            if not title or not description or priority not in {"low", "medium", "high"}:
                flash("Title, description, and a valid priority are required.", "error")
                return render_template("new_ticket.html"), 400

            ticket = execute_returning(
                """
                INSERT INTO tickets (title, description, priority, created_by)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (title, description, priority, session["user_id"]),
            )
            flash("Ticket created.", "success")
            return redirect(url_for("ticket_detail", ticket_id=ticket["id"]))
        return render_template("new_ticket.html")

    @app.get("/tickets/<int:ticket_id>")
    @login_required
    def ticket_detail(ticket_id: int) -> str:
        # VULN-3: IDOR - ticket ownership is not checked on detail access.
        ticket = fetch_one(
            """
            SELECT t.id, t.title, t.description, t.status, t.priority, t.created_at,
                   t.created_by, u.username AS creator, a.username AS assignee
            FROM tickets t
            JOIN users u ON u.id = t.created_by
            LEFT JOIN users a ON a.id = t.assigned_to
            WHERE t.id = %s
            """,
            (ticket_id,),
        )
        if ticket is None:
            abort(404)
        comments = fetch_all(
            """
            SELECT c.id, c.body, c.created_at, u.username
            FROM comments c
            JOIN users u ON u.id = c.user_id
            WHERE c.ticket_id = %s
            ORDER BY c.created_at ASC
            """,
            (ticket_id,),
        )
        return render_template("ticket_detail.html", ticket=ticket, comments=comments)

    @app.post("/tickets/<int:ticket_id>/comment")
    @login_required
    def add_comment(ticket_id: int) -> object:
        ticket = fetch_one("SELECT id, created_by FROM tickets WHERE id = %s", (ticket_id,))
        if ticket is None:
            abort(404)
        if not can_manage_ticket(ticket):
            return "Forbidden", 403
        body = request.form.get("body", "").strip()
        if not body:
            flash("Comment cannot be empty.", "error")
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        execute(
            "INSERT INTO comments (ticket_id, user_id, body) VALUES (%s, %s, %s)",
            (ticket_id, session["user_id"], body),
        )
        flash("Comment added.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.post("/tickets/<int:ticket_id>/assign")
    @role_required("agent", "admin")
    def assign_ticket(ticket_id: int) -> object:
        assignee_id = request.form.get("assignee_id", type=int)
        if assignee_id is None:
            return "A valid assignee is required", 400
        if fetch_one("SELECT id FROM tickets WHERE id = %s", (ticket_id,)) is None:
            abort(404)
        assignee = fetch_one(
            "SELECT id FROM users WHERE id = %s AND role IN ('agent', 'admin')",
            (assignee_id,),
        )
        if assignee is None:
            return "Invalid assignee", 400
        execute("UPDATE tickets SET assigned_to = %s WHERE id = %s", (assignee_id, ticket_id))
        flash("Ticket assigned.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.post("/tickets/<int:ticket_id>/close")
    @role_required("agent", "admin")
    def close_ticket(ticket_id: int) -> object:
        if fetch_one("SELECT id FROM tickets WHERE id = %s", (ticket_id,)) is None:
            abort(404)
        execute("UPDATE tickets SET status = 'closed' WHERE id = %s", (ticket_id,))
        flash("Ticket closed.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

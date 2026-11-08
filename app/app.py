import base64
from functools import wraps
import os
import pickle
import subprocess
from datetime import datetime
from typing import Callable, TypeVar
from urllib.request import urlopen

from flask import (
    Flask,
    abort,
    flash,
    make_response,
    redirect,
    render_template,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from db import execute, execute_returning, fetch_all, fetch_one

ViewFunction = TypeVar("ViewFunction", bound=Callable[..., object])


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    @app.after_request
    def log_request(response: object) -> object:
        username = session.get("username", "anonymous")
        app.logger.info(
            "request timestamp=%s method=%s path=%s status=%s username=%s",
            datetime.now().isoformat(),
            request.method,
            request.path,
            getattr(response, "status_code", "unknown"),
            username,
        )
        return response

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
    def hello() -> object:
        if "user_id" in session:
            return redirect(url_for("tickets"))
        return redirect(url_for("login"))

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
        return render_template("status.html", heading="Agent area", message="Manage and resolve customer tickets.")

    @app.get("/admin")
    @role_required("admin")
    def admin_home() -> str:
        return render_template("status.html", heading="Admin area", message="Manage HelpDesk users and access.")

    @app.route("/search")
    @login_required
    def search() -> str:
        query_text = request.args.get("q", "")
        app.logger.info("search query=%s", query_text)
        # VULN-1: SQL injection - the search input is interpolated into SQL.
        visibility = (
            ""
            if session.get("role") in {"agent", "admin"}
            else f"AND t.created_by = {session['user_id']}"
        )
        query = f"""
            SELECT t.id, t.title, t.status, t.priority, t.created_at,
                   u.username AS creator
            FROM tickets t
            JOIN users u ON u.id = t.created_by
            WHERE t.title ILIKE '%{query_text}%' {visibility}
            ORDER BY t.created_at DESC
        """
        results = fetch_all(query)
        return render_template("search.html", tickets=results, query=query_text)

    @app.route("/admin/users")
    @login_required
    def admin_users() -> str:
        # VULN-4: Privilege escalation - only login is checked, not admin role.
        users = fetch_all(
            "SELECT id, username, email, role, created_at FROM users ORDER BY id"
        )
        return render_template("admin_users.html", users=users)

    @app.post("/admin/users/<int:user_id>/role")
    @login_required
    def update_user_role(user_id: int) -> object:
        # VULN-4: Privilege escalation - only login is checked, not admin role.
        role = request.form.get("role", "")
        if role not in {"user", "agent", "admin"}:
            return "Invalid role", 400
        if fetch_one("SELECT id FROM users WHERE id = %s", (user_id,)) is None:
            abort(404)
        execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))
        flash("User role updated.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/diagnostics", methods=["GET", "POST"])
    @login_required
    def diagnostics() -> str:
        output = ""
        host = ""
        if request.method == "POST":
            host = request.form.get("host", "")
            app.logger.info("diagnostics host=%s", host)
            ping_flag = "-n" if os.name == "nt" else "-c"
            # VULN-8: OS command injection through shell=True and interpolated input.
            command = f"ping {ping_flag} 1 {host}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            output = result.stdout + result.stderr
        return render_template("diagnostics.html", output=output, host=host)

    @app.route("/tickets/<int:ticket_id>/preview", methods=["GET", "POST"])
    @login_required
    def ticket_preview(ticket_id: int) -> str:
        ticket = fetch_one(
            "SELECT id, title, description, status, priority FROM tickets WHERE id = %s",
            (ticket_id,),
        )
        if ticket is None:
            abort(404)
        template_text = request.form.get("template", "") if request.method == "POST" else ""
        rendered_output = ""
        if request.method == "POST":
            app.logger.info("preview template=%s", template_text)
            # VULN-10: SSTI
            rendered_output = render_template_string(template_text, ticket=ticket)
        return render_template(
            "ticket_preview.html",
            ticket=ticket,
            template_text=template_text,
            rendered_output=rendered_output,
        )

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

    @app.post("/tickets/save-preset")
    @login_required
    def save_preset() -> object:
        preset = {
            "status": request.form.get("status", ""),
            "priority": request.form.get("priority", ""),
        }
        encoded_preset = base64.b64encode(pickle.dumps(preset)).decode("ascii")
        response = make_response(redirect(url_for("tickets")))
        response.set_cookie("ticket_preset", encoded_preset)
        flash("Ticket filter preset saved.", "success")
        return response

    @app.get("/tickets/load-preset")
    @login_required
    def load_preset() -> str:
        encoded_preset = request.cookies.get("ticket_preset", "")
        preset = None
        if encoded_preset:
            # VULN-11: Insecure deserialization (pickle)
            preset = pickle.loads(base64.b64decode(encoded_preset))
        app.logger.info("ticket preset loaded username=%s", session.get("username", "anonymous"))
        return render_template("ticket_preset.html", preset=preset)

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
        attachments = fetch_all(
            """
            SELECT id, source_url, content, created_at
            FROM attachments
            WHERE ticket_id = %s
            ORDER BY created_at ASC
            """,
            (ticket_id,),
        )
        return render_template(
            "ticket_detail.html",
            ticket=ticket,
            comments=comments,
            attachments=attachments,
        )

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

    @app.post("/tickets/<int:ticket_id>/attach-url")
    @login_required
    def attach_url(ticket_id: int) -> object:
        ticket = fetch_one("SELECT id, created_by FROM tickets WHERE id = %s", (ticket_id,))
        if ticket is None:
            abort(404)
        if not can_manage_ticket(ticket):
            return "Forbidden", 403
        source_url = request.form.get("url", "")
        app.logger.info("attach-url url=%s", source_url)
        # VULN-9: SSRF - fetches an arbitrary URL without scheme or host checks.
        with urlopen(source_url, timeout=5) as response:
            content = response.read(20000).decode("utf-8", errors="replace")[:2000]
        execute(
            """
            INSERT INTO attachments (ticket_id, source_url, content)
            VALUES (%s, %s, %s)
            """,
            (ticket_id, source_url, content),
        )
        flash("Link attached.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    return app


app = create_app()


if __name__ == "__main__":
    debug_value = os.environ.get("FLASK_DEBUG", "1").lower() in {"1", "true", "yes", "on"}
    # VULN-6: Debug mode is enabled by default.
    app.run(host=os.environ.get("FLASK_HOST", "127.0.0.1"), port=5000, debug=debug_value)

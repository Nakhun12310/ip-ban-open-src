# app.py

from datetime import datetime, timezone
from functools import wraps
from ipaddress import ip_address, ip_network

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)

app.config["SECRET_KEY"] = "change-this-to-a-long-random-secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# -------------------------
# models
# -------------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_banned = db.Column(db.Boolean, default=False, nullable=False)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class UserIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
    )

    ip = db.Column(db.String(45), nullable=False)
    first_seen = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    user = db.relationship("User", backref="ips")


class IPBan(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Supports both:
    # 203.0.113.10
    # 203.0.113.0/24
    network = db.Column(db.String(50), unique=True, nullable=False)

    reason = db.Column(db.String(255), nullable=True)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# -------------------------
# ip handling
# -------------------------

def get_client_ip():
    """
    request.access_route is ordered client -> proxy -> ...

    IMPORTANT:
    Only use this when your reverse proxy is configured to
    overwrite/validate the forwarded headers.
    """

    if request.access_route:
        return request.access_route[0]

    return request.remote_addr


def normalize_network(value):
    """
    Converts an IP or CIDR into canonical CIDR notation.
    """

    value = value.strip()

    try:
        # Individual IP
        addr = ip_address(value)

        if addr.version == 4:
            return f"{addr}/32"

        return f"{addr}/128"

    except ValueError:
        pass

    try:
        network = ip_network(value, strict=False)
        return str(network)

    except ValueError:
        return None


def is_ip_banned(ip):
    """
    Checks an IP against every configured IP/network ban.
    """

    try:
        address = ip_address(ip)
    except ValueError:
        return False

    bans = IPBan.query.all()

    for ban in bans:
        try:
            network = ip_network(ban.network, strict=False)

            if address in network:
                return True

        except ValueError:
            continue

    return False


def get_matching_ban(ip):
    try:
        address = ip_address(ip)
    except ValueError:
        return None

    for ban in IPBan.query.all():
        try:
            network = ip_network(ban.network, strict=False)

            if address in network:
                return ban

        except ValueError:
            continue

    return None


# -------------------------
# account/ip linking
# -------------------------

def record_user_ip(user):
    """
    Associates the current IP with the account.
    """

    ip = get_client_ip()

    if not ip:
        return

    existing = UserIP.query.filter_by(
        user_id=user.id,
        ip=ip,
    ).first()

    now = datetime.now(timezone.utc)

    if existing:
        existing.last_seen = now
    else:
        db.session.add(
            UserIP(
                user_id=user.id,
                ip=ip,
            )
        )

    db.session.commit()


# -------------------------
# automatic ban enforcement
# -------------------------

@app.before_request
def enforce_ip_ban():
    """
    Runs before normal routes.

    Admin pages are also protected unless the current user
    is an admin. This prevents a banned normal account from
    accessing the site.
    """

    # Don't interfere with static files.
    if request.endpoint == "static":
        return

    ip = get_client_ip()

    if not ip:
        return

    ban = get_matching_ban(ip)

    if not ban:
        return

    # Allow the admin panel to inspect/remove the ban.
    if current_user.is_authenticated and current_user.is_admin:
        return

    # If a logged-in account is coming from a banned IP,
    # mark that account banned as well.
    if current_user.is_authenticated:
        if not current_user.is_banned:
            current_user.is_banned = True
            db.session.commit()

    return (
        render_template(
            "banned.html",
            ban=ban,
        ),
        403,
    )


# -------------------------
# login
# -------------------------

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if not user:
            flash("invalid username or password")
            return redirect(url_for("login"))

        if user.is_banned:
            return render_template(
                "banned.html",
                ban=None,
            ), 403

        # Extra check in case the IP became banned.
        if is_ip_banned(get_client_ip()):
            return render_template(
                "banned.html",
                ban=get_matching_ban(get_client_ip()),
            ), 403

        if not check_password_hash(
            user.password_hash,
            password,
        ):
            flash("invalid username or password")
            return redirect(url_for("login"))

        login_user(user)

        record_user_ip(user)

        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("login"))


# -------------------------
# signup
# -------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("username and password are required")
            return redirect(url_for("register"))

        client_ip = get_client_ip()

        # Never create an account from a banned IP/network.
        if is_ip_banned(client_ip):
            return render_template(
                "banned.html",
                ban=get_matching_ban(client_ip),
            ), 403

        if User.query.filter_by(username=username).first():
            flash("username already exists")
            return redirect(url_for("register"))

        user = User(
            username=username,
            password_hash=generate_password_hash(password),
        )

        db.session.add(user)
        db.session.commit()

        record_user_ip(user)

        login_user(user)

        return redirect(url_for("index"))

    return render_template("register.html")


# -------------------------
# normal site
# -------------------------

@app.route("/")
def index():
    return "your site goes here"


# -------------------------
# admin protection
# -------------------------

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):

        if not current_user.is_authenticated:
            return redirect(url_for("login"))

        if not current_user.is_admin:
            abort(403)

        return view(*args, **kwargs)

    return wrapped


# -------------------------
# admin dashboard
# -------------------------

@app.route("/admin/bans")
@login_required
@admin_required
def admin_bans():

    bans = IPBan.query.order_by(
        IPBan.created_at.desc()
    ).all()

    users = User.query.order_by(
        User.created_at.desc()
    ).all()

    return render_template(
        "admin_bans.html",
        bans=bans,
        users=users,
    )


# -------------------------
# create ban
# -------------------------

@app.route("/admin/bans/add", methods=["POST"])
@login_required
@admin_required
def add_ban():

    value = request.form.get("network", "").strip()
    reason = request.form.get("reason", "").strip()

    normalized = normalize_network(value)

    if not normalized:
        flash("invalid ip or network")
        return redirect(url_for("admin_bans"))

    existing = IPBan.query.filter_by(
        network=normalized
    ).first()

    if existing:
        flash("that network is already banned")
        return redirect(url_for("admin_bans"))

    ban = IPBan(
        network=normalized,
        reason=reason or None,
    )

    db.session.add(ban)
    db.session.commit()

    flash(f"banned {normalized}")

    return redirect(url_for("admin_bans"))


# -------------------------
# remove ban
# -------------------------

@app.route("/admin/bans/<int:ban_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_ban(ban_id):

    ban = db.session.get(IPBan, ban_id)

    if not ban:
        abort(404)

    db.session.delete(ban)
    db.session.commit()

    flash("ban removed")

    return redirect(url_for("admin_bans"))



@app.route("/admin/users/<int:user_id>/ban", methods=["POST"])
@login_required
@admin_required
def ban_user(user_id):

    user = db.session.get(User, user_id)

    if not user:
        abort(404)

    user.is_banned = True

    db.session.commit()

    flash(f"banned account {user.username}")

    return redirect(url_for("admin_bans"))



@app.route("/admin/users/<int:user_id>/unban", methods=["POST"])
@login_required
@admin_required
def unban_user(user_id):

    user = db.session.get(User, user_id)

    if not user:
        abort(404)

    user.is_banned = False

    db.session.commit()

    flash(f"unbanned account {user.username}")

    return redirect(url_for("admin_bans"))



with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)

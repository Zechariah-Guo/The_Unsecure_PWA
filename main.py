import os
import re
from io import BytesIO
from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import session
from flask_wtf.csrf import CSRFProtect
import pyotp
import qrcode
import qrcode.image.svg
import user_management as dbHandler

# Code snippet for logging a message
# app.logger.critical("message")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")
csrf = CSRFProtect(app)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
PASSWORD_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,64}$")
ALLOWED_REDIRECTS = {
    "/",
    "/index.html",
    "/signup.html",
    "/success.html",
    "/logout",
    "/2fa/setup",
    "/2fa/verify",
}
ALLOWED_MESSAGES = {
    "Invalid redirect",
    "Please log in",
    "Account created. You can enable 2FA after login.",
    "Logged out",
    "2FA already enabled",
    "2FA not enabled",
}


def _is_valid_username(username):
    return bool(USERNAME_RE.fullmatch(username or ""))


def _sanitize_message(msg):
    """Validate message against whitelist to prevent injection attacks."""
    if msg in ALLOWED_MESSAGES:
        return msg
    return ""


def _is_valid_password(password):
    return bool(PASSWORD_RE.fullmatch(password or ""))


def _safe_redirect(target):
    if target in ALLOWED_REDIRECTS:
        return redirect(target, code=302)
    app.logger.warning("Blocked untrusted redirect: %s", target)
    return redirect("/index.html?msg=Invalid redirect", code=302)


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def _build_qr_code_svg(username, secret):
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name="Unsecure PWA"
    )
    qr = qrcode.QRCode(image_factory=qrcode.image.svg.SvgPathImage)
    qr.add_data(otp_uri)
    qr.make(fit=True)
    stream = BytesIO()
    img = qr.make_image()
    img.save(stream)
    return stream.getvalue().decode("utf-8")


def _should_show_2fa_cta(username):
    enabled, _ = dbHandler.get_2fa_status(username)
    return not enabled


@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if not session.get("user"):
        return redirect("/index.html?msg=Please log in")
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return _safe_redirect(url)
    if request.method == "POST":
        feedback = request.form.get("feedback", "").strip()
        if not feedback:
            return render_template(
                "/success.html",
                state=True,
                value=session.get("user"),
                msg="Feedback is required.",
                show_2fa_cta=_should_show_2fa_cta(session.get("user")),
            )
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template(
            "/success.html",
            state=True,
            value=session.get("user"),
            show_2fa_cta=_should_show_2fa_cta(session.get("user")),
        )
    else:
        dbHandler.listFeedback()
        return render_template(
            "/success.html",
            state=True,
            value=session.get("user"),
            show_2fa_cta=_should_show_2fa_cta(session.get("user")),
        )


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return _safe_redirect(url)
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not _is_valid_username(username):
            return render_template("/signup.html", msg="Invalid username.")
        if not _is_valid_password(password):
            return render_template("/signup.html", msg="Weak password.")
        dbHandler.insertUser(username, password)
        return redirect(
            "/index.html?msg=Account created. You can enable 2FA after login."
        )
    else:
        return render_template("/signup.html")


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    # Simple Dynamic menu
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return _safe_redirect(url)
    # Pass message to front end
    elif request.method == "GET":
        msg = _sanitize_message(request.args.get("msg", ""))
        return render_template("/index.html", msg=msg, state=bool(session.get("user")))
    elif request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not _is_valid_username(username) or not password:
            return render_template("/index.html", msg="Invalid credentials.")
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            enabled, _ = dbHandler.get_2fa_status(username)
            if enabled:
                session["pending_user"] = username
                return redirect("/2fa/verify")
            session["user"] = username
            dbHandler.listFeedback()
            return render_template(
                "/success.html",
                value=username,
                state=True,
                show_2fa_cta=True,
            )
        else:
            app.logger.warning("Failed login attempt for username: %s", username)
            return render_template("/index.html", msg="Login failed.")
    else:
        return render_template("/index.html")


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect("/index.html?msg=Logged out")


@app.route("/2fa/setup", methods=["GET", "POST"])
def two_factor_setup():
    username = session.get("user")
    if not username:
        return redirect("/index.html?msg=Please log in")

    enabled, _ = dbHandler.get_2fa_status(username)
    if enabled:
        return redirect("/success.html?msg=2FA already enabled")

    if request.method == "POST":
        secret = session.get("setup_secret")
        if not secret:
            return redirect("/2fa/setup")
        otp_input = request.form.get("otp", "").strip()
        if pyotp.TOTP(secret).verify(otp_input):
            dbHandler.enable_2fa(username, secret)
            session.pop("setup_secret", None)
            dbHandler.listFeedback()
            return render_template(
                "/success.html",
                value=username,
                state=True,
                show_2fa_cta=False,
                msg="2FA enabled successfully.",
            )
        return render_template(
            "/2fa.html",
            value=username,
            qr_code_svg=_build_qr_code_svg(username, secret),
            secret=secret,
            state=True,
            msg="Invalid code. Try again.",
        )

    session["setup_secret"] = pyotp.random_base32()
    return render_template(
        "/2fa.html",
        value=username,
        qr_code_svg=_build_qr_code_svg(username, session["setup_secret"]),
        secret=session["setup_secret"],
        state=True,
    )


@app.route("/2fa/verify", methods=["GET", "POST"])
def two_factor_verify():
    pending_user = session.get("pending_user")
    if not pending_user:
        return redirect("/index.html?msg=Please log in")

    enabled, secret = dbHandler.get_2fa_status(pending_user)
    if not enabled or not secret:
        session.pop("pending_user", None)
        return redirect("/index.html?msg=2FA not enabled")

    if request.method == "POST":
        otp_input = request.form.get("otp", "").strip()
        if pyotp.TOTP(secret).verify(otp_input):
            session.pop("pending_user", None)
            session["user"] = pending_user
            dbHandler.listFeedback()
            return render_template(
                "/success.html",
                value=pending_user,
                state=True,
                show_2fa_cta=False,
            )
        return render_template(
            "/2fa_verify.html",
            value=pending_user,
            state=False,
            msg="Invalid code. Try again.",
        )

    return render_template("/2fa_verify.html", value=pending_user, state=False)


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)

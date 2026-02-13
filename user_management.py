import html
import sqlite3 as sql
import portalocker
from werkzeug.security import generate_password_hash, check_password_hash

DUMMY_PASSWORD_HASH = generate_password_hash("invalid-password")


def insertUser(username, password, DoB):
    password_hash = generate_password_hash(password)
    with sql.connect("database_files/database.db") as con:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO users (username,password,dateOfBirth,otp_enabled) VALUES (?,?,?,?)",
            (username, password_hash, DoB, 0),
        )


def retrieveUsers(username, password):
    with sql.connect("database_files/database.db") as con:
        cur = con.cursor()
        cur.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row is None:
            check_password_hash(DUMMY_PASSWORD_HASH, password)
            return False
        stored_hash = row[0]
        if not check_password_hash(stored_hash, password):
            return False

        # Plain text log of visitor count as requested by Unsecure PWA management
        with portalocker.Lock("visitor_log.txt", "r+", timeout=2) as file:
            content = file.read().strip()
            number = int(content) if content else 0
            number += 1
            file.seek(0)
            file.truncate()
            file.write(str(number))

        return True


def insertFeedback(feedback):
    with sql.connect("database_files/database.db") as con:
        cur = con.cursor()
        cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))


def listFeedback():
    with sql.connect("database_files/database.db") as con:
        cur = con.cursor()
        data = cur.execute("SELECT * FROM feedback").fetchall()
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        safe_feedback = html.escape(str(row[1]))
        f.write("<p>\n")
        f.write(f"{safe_feedback}\n")
        f.write("</p>\n")
    f.close()


def get_2fa_status(username):
    with sql.connect("database_files/database.db") as con:
        cur = con.cursor()
        cur.execute(
            "SELECT otp_enabled, otp_secret FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
    if row is None:
        return False, None
    return bool(row[0]), row[1]


def enable_2fa(username, secret):
    with sql.connect("database_files/database.db") as con:
        cur = con.cursor()
        cur.execute(
            "UPDATE users SET otp_secret = ?, otp_enabled = 1 WHERE username = ?",
            (secret, username),
        )

from http.server import SimpleHTTPRequestHandler, HTTPServer
from functools import partial
import json
import os

from config import PORT
from core.database import init, connect
from core.auth import hash_password, create_session, verify_session, destroy_session
from core.fraud_engine import analyze_input
from core.abuse import rate_limited

# ---------------------------------------
# INITIAL SETUP
# ---------------------------------------
init()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ---------------------------------------
# SERVER CLASS
# ---------------------------------------
class Server(SimpleHTTPRequestHandler):

    def do_POST(self):

        # ---------------- RATE LIMIT ----------------
        client_ip = self.client_address[0]
        if rate_limited(client_ip):
            self.send_error(429, "Too many requests")
            return

        length = int(self.headers.get("Content-Length", 0))
        raw_data = self.rfile.read(length)

        try:
            data = json.loads(raw_data)
        except:
            data = {}

        # ---------- REGISTER ----------
        if self.path == "/api/register":
            db = connect()
            try:
                db.execute(
                    "INSERT INTO users(email,password,role) VALUES(?,?,?)",
                    (data["email"], hash_password(data["password"]), "user")
                )
                db.commit()
                self.respond({"success": True})
            except:
                self.respond({"error": "User already exists"}, 400)
            finally:
                db.close()

        # ---------- LOGIN ----------
        elif self.path == "/api/login":
            db = connect()
            row = db.execute(
                "SELECT id,password,role FROM users WHERE email=?",
                (data.get("email"),)
            ).fetchone()
            db.close()

            if row and hash_password(data.get("password", "")) == row[1]:
                token = create_session(row[0], row[2])
                self.respond({
                    "token": token,
                    "role": row[2],
                    "user_id": row[0]
                })
            else:
                self.respond({"error": "Invalid credentials"}, 401)

        # ---------- USER HISTORY ----------
        elif self.path == "/api/user/history":
            token = self.headers.get("Authorization")
            session = verify_session(token)

            if not session:
                self.respond({"error": "Unauthorized"}, 403)
                return

            db = connect()
            logs = db.execute(
                "SELECT input,result,confidence FROM logs WHERE user_id=?",
                (session["user_id"],)
            ).fetchall()
            db.close()

            history = [
                {
                    "input": row[0],
                    "result": row[1],
                    "confidence": row[2]
                }
                for row in logs
            ]

            self.respond({"history": history})

        # ---------- VERIFY ----------
        elif self.path == "/api/verify":
            analysis = analyze_input(
                url=data.get("url"),
                text=data.get("text"),
                filename=data.get("filename")
            )

            if data.get("consent") and data.get("user_id"):
                db = connect()
                db.execute(
                    """INSERT INTO logs(user_id,input,result,confidence)
                       VALUES (?,?,?,?)""",
                    (
                        data["user_id"],
                        data.get("url") or data.get("filename") or "N/A",
                        analysis["status"],
                        analysis["confidence"]
                    )
                )
                db.commit()
                db.close()

            self.respond({
                "status": analysis["status"],
                "confidence": analysis["confidence"],
                "risk_score": analysis["risk_score"],
                "reasons": analysis["reasons"]
            })

        # ---------- ADMIN STATS ----------
        elif self.path == "/api/admin/stats":
            token = self.headers.get("Authorization")
            session = verify_session(token)

            if not session or session["role"] != "admin":
                self.respond({"error": "Unauthorized"}, 403)
                return

            db = connect()
            fraud = db.execute(
                "SELECT COUNT(*) FROM logs WHERE result='FRAUDULENT'"
            ).fetchone()[0]
            legit = db.execute(
                "SELECT COUNT(*) FROM logs WHERE result='LEGITIMATE'"
            ).fetchone()[0]
            db.close()

            self.respond({
                "fraud": fraud,
                "legit": legit
            })

        # ---------- PROFILE ----------
        elif self.path == "/api/profile":
            token = self.headers.get("Authorization")
            session = verify_session(token)

            if not session:
                self.respond({"error": "Unauthorized"}, 403)
                return

            db = connect()
            user = db.execute(
                "SELECT email, role FROM users WHERE id=?",
                (session["user_id"],)
            ).fetchone()
            db.close()

            if not user:
                self.respond({"error": "User not found"}, 404)
                return

            self.respond({
                "email": user[0],
                "role": user[1]
            })

        # ---------- DELETE ACCOUNT ----------
        elif self.path == "/api/delete-account":
            token = self.headers.get("Authorization")
            session = verify_session(token)

            if not session:
                self.respond({"error": "Unauthorized"}, 403)
                return

            db = connect()

            db.execute("DELETE FROM logs WHERE user_id=?", (session["user_id"],))
            db.execute("DELETE FROM users WHERE id=?", (session["user_id"],))

            db.commit()
            db.close()

            destroy_session(token)

            self.respond({"success": True})

        # ---------- CHANGE PASSWORD ----------
        elif self.path == "/api/change-password":
            token = self.headers.get("Authorization")
            session = verify_session(token)

            if not session:
                self.respond({"error": "Unauthorized"}, 403)
                return

            old_password = data.get("old_password")
            new_password = data.get("new_password")

            if not old_password or not new_password:
                self.respond({"error": "All fields required"}, 400)
                return

            db = connect()
            row = db.execute(
                "SELECT password FROM users WHERE id=?",
                (session["user_id"],)
            ).fetchone()

            if not row or hash_password(old_password) != row[0]:
                db.close()
                self.respond({"error": "Old password incorrect"}, 400)
                return

            db.execute(
                "UPDATE users SET password=? WHERE id=?",
                (hash_password(new_password), session["user_id"])
            )
            db.commit()
            db.close()

            self.respond({"success": True})

        # ---------- FEEDBACK ----------
        elif self.path == "/api/feedback":
            db = connect()
            db.execute(
                "INSERT INTO feedback(name,email,message) VALUES(?,?,?)",
                (
                    data.get("name"),
                    data.get("email"),
                    data.get("message")
                )
            )
            db.commit()
            db.close()
            self.respond({"success": True})

        # ---------- LOGOUT ----------
        elif self.path == "/api/logout":
            token = self.headers.get("Authorization")
            session = verify_session(token)

            if not session:
                self.respond({"error": "Unauthorized"}, 403)
                return

            destroy_session(token)
            self.respond({"success": True})

        else:
            self.send_error(404, "API endpoint not found")

    # -------------------------------
    # JSON RESPONSE HELPER
    # -------------------------------
    def respond(self, payload, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())


# ---------------------------------------
# START SERVER
# ---------------------------------------
Handler = partial(Server, directory=PUBLIC_DIR)

print(f"Server running at http://localhost:{PORT}")
HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
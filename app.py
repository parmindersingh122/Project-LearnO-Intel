import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------------
# Database setup
# -----------------------------
conn = sqlite3.connect("lerno.db", check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    registered_on TEXT NOT NULL,
    last_login TEXT
)
""")
conn.commit()

# -----------------------------
# Helper Functions
# -----------------------------
def register_user(username, password, role="user"):
    hashed_password = generate_password_hash(password)
    registered_on = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        c.execute("INSERT INTO users (username, password, role, registered_on) VALUES (?, ?, ?, ?)",
                  (username, hashed_password, role, registered_on))
        conn.commit()
        return True, "✅ User registered successfully!"
    except sqlite3.IntegrityError:
        return False, "⚠️ Username already exists."

def login_user(username, password):
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    if user and check_password_hash(user[2], password):
        last_login = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("UPDATE users SET last_login=? WHERE id=?", (last_login, user[0]))
        conn.commit()
        return True, {"id": user[0], "username": user[1], "role": user[3], "registered_on": user[4], "last_login": last_login}
    return False, "Invalid username or password."

def get_all_users():
    c.execute("SELECT id, username, role, registered_on, last_login FROM users")
    rows = c.fetchall()
    return pd.DataFrame(rows, columns=["User ID", "Username", "Role", "Registered On", "Last Login"])

# -----------------------------
# Streamlit App
# -----------------------------
st.set_page_config(page_title="LearnO-Intel Auth System", layout="centered")

st.title("🔐 LearnO-Intel User System")
st.write("Register, Login, and View Dashboard")

# Initialize session
if "user" not in st.session_state:
    st.session_state.user = None

menu = ["Home", "Register", "Login", "Dashboard"]
choice = st.sidebar.selectbox("Menu", menu)

# Home
if choice == "Home":
    st.subheader("Welcome to LearnO-Intel")
    st.write("A simple AI Tutor app with user authentication (built on Streamlit).")

# Register
elif choice == "Register":
    st.subheader("Create New Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["user", "admin"])
    if st.button("Register"):
        success, msg = register_user(username, password, role)
        if success:
            st.success(msg)
        else:
            st.error(msg)

# Login
elif choice == "Login":
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        success, result = login_user(username, password)
        if success:
            st.session_state.user = result
            st.success(f"Welcome {result['username']}! You are logged in as {result['role']}.")
        else:
            st.error(result)

# Dashboard
elif choice == "Dashboard":
    if st.session_state.user:
        user = st.session_state.user
        st.subheader(f"📊 Dashboard - {user['username']}")
        st.write(f"**Role:** {user['role']}")
        st.write(f"**Registered On:** {user['registered_on']}")
        st.write(f"**Last Login:** {user['last_login']}")

        if user["role"] == "admin":
            st.subheader("👥 All Users")
            df = get_all_users()
            st.dataframe(df)
    else:
        st.warning("⚠️ Please login first.")

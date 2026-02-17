import sqlite3
from config import DB_NAME

def connect():
    return sqlite3.connect(DB_NAME)

def init():
    db = connect()
    c = db.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        input TEXT,
        result TEXT,
        confidence INTEGER,
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS feedback(
        id INTEGER PRIMARY KEY,
        name TEXT,
        email TEXT,
        message TEXT
    )""")

    db.commit()
    db.close()

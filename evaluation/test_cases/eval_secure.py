import sqlite3
import subprocess
import os

def safe_query(cursor: sqlite3.Cursor, uid: str):
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return cursor.fetchall()

def safe_ping(host: str):
    subprocess.run(["ping", "-c", "1", host], shell=False)

def safe_secret():
    return os.environ.get("SECRET_KEY", "")

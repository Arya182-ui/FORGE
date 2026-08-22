import sqlite3

def get_user_by_username_secure(cursor: sqlite3.Cursor, username: str):
    # Secure parameterized query
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()

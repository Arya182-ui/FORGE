import sqlite3

def get_user(cursor: sqlite3.Cursor, user_id: str):
    # Expected SQLi at line 6
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()

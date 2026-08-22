import sqlite3

def get_user_by_username(cursor: sqlite3.Cursor, username: str):
    # Vulnerable f-string SQL query concatenation
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def search_products(cursor: sqlite3.Cursor, category: str):
    # Vulnerable % string formatting
    query = "SELECT * FROM products WHERE category = '%s'" % category
    cursor.execute(query)
    return cursor.fetchall()

import sqlite3

def get_user_data(user_id: str):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # Vulnerable SQL injection query matching our chained_sqli.yaml pattern
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()

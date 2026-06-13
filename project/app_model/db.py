import _sqlite3, pandas as pd

def create_user_table(conn):
    
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT NOT NULL UNIQUE,
                   password_hash TEXT NOT NULL,
                   role TEXT DEFAULT 'user'
    );
    """)

    conn.commit()

def get_connection():

    conn= _sqlite3.connect('DATA/project_data.db')
    return conn


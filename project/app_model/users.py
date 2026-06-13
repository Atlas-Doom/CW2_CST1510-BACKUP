import _sqlite3, pandas as pd

def add_user(conn,username,hashed_password):
    cursor= conn.cursor()

    cursor.execute(
        """
        INSERT INTO users (username,password_hash) 
        VALUES(?,?)
        """,
        (username,hashed_password)
    )
    conn.commit()

def get_all_users(conn):
    cur=conn.cursor()
    cur.execute('SELECT * FROM users')
    return cur.fetchall()

def get_user(conn,username):
    cur= conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = ?' ,
(username,))
    return cur.fetchone()

def update_user(conn, old_name, new_name):
    cur = conn.cursor()
    cur.execute('UPDATE users SET username = ? WHERE username = ?', (new_name, old_name))
    conn.commit()

def delete_user(conn,user_name):
    cur = conn.cursor()
    cur.execute('DELETE FROM users WHERE username = ?',(user_name,))
    conn.commit()


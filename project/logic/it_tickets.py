from app_model.db import get_connection
import pandas as pd

def get_all_tickets():
    conn= get_connection()
    return pd.read_sql(
        "SELECT * FROM it_tickets",
        conn
    )
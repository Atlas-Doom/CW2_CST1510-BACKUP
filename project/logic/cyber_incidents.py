from app_model.db import get_connection
import pandas as pd

def get_all_incidents():
    conn= get_connection()
    return pd.read_sql(
        "SELECT * FROM cyber_incidents",
        conn
    )

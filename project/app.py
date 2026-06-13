import bcrypt


from app_model.users import get_user
from app_model.users import delete_user
from app_model.users import update_user
from app_model.db import get_connection
from app_model.users import add_user
from app_model.users import get_all_users
from app_model.db import create_user_table

conn=get_connection()
create_user_table(conn)


def passwordhash(password):
        pw_bytes= password.encode('utf-8')
        salt= bcrypt.gensalt()
        hashed_pw= bcrypt.hashpw(pw_bytes,salt)
        return hashed_pw

def passwordcheck(password,hashed_pw):
      password_byte=password.encode("utf-8")
      return bcrypt.checkpw(password_byte,hashed_pw)

def register(username,password):

    username_exists = get_user(conn,username)     
    if username_exists:
          return False
                      
    hashed_password=passwordhash(password)
    add_user(conn,username,hashed_password)
    return True

def login(username,password):
      
      logging_in= get_user(conn,username)
      if logging_in:

            stored_hash= logging_in[2]

            if passwordcheck(password,stored_hash):
                  return True
      return False

import streamlit as st

if 'logged_in' not in st.session_state:
      st.session_state.logged_in = False

if 'username' not in st.session_state:
      st.session_state.username = None

if not st.session_state.logged_in:

      st.title("🔐 User Authentication System")
      st.write("Please Login or Register")


if not st.session_state.logged_in:

      page = st.sidebar.selectbox(
      "Choose an option",
      ["Login", "Register"]
      )

      if page == 'Register':
            st.header('Create an Acccount')

            username= st.text_input("Username")
            password=st.text_input("Create password",type="password")

            if st.button("Register"):
                  if register(username,password):
                        st.success("Account created!")
                  else:  st.error("Username already exists!")


      if page == "Login":
            st.header("Login🔑")

            username= st.text_input("Username")
            password=st.text_input("Password",type="password")

            if st.button("Login"):

                  if login(username,password):
                        st.session_state.logged_in=True
                        st.session_state.username=username
                        st.rerun()

                  else:  st.error("Incorrect Username or Password")

else:
      page=st.sidebar.selectbox(
            "Dashboard",
            [
                  "Cyber Incidents",
                  "IT Tickets",
                  "Metadata",
                  "AI Chatbot",
            ]
      )

# UI
st.sidebar.write('-------------------------')


if  st.sidebar.button('Logout ➜]'):

      st.session_state.logged_in=False
      st.session_state.username=None
      st.rerun()


if st.session_state.logged_in:
      st.title("Dashboard")
      st.write(f"Welcome {st.session_state.username}")



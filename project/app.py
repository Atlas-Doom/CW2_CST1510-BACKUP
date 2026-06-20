import bcrypt


from app_model.users import get_user
from app_model.users import delete_user
from app_model.users import update_user
from app_model.db import get_connection
from app_model.users import add_user
from app_model.users import get_all_users
from app_model.db import create_user_table
from app_model.users import for_code
from app_model.users import get_mail

import streamlit as st

st.set_page_config (
      page_title="Security Intelligence Platform",
      page_icon='🛡️',
      layout="wide"
)

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

def register(username,password,email):

    username_exists = get_user(conn,username)     
    if username_exists:
          return False
                      
    hashed_password=passwordhash(password)
    add_user(conn,username,hashed_password,email)
    return True

def login(username,password):
      
      logging_in= get_user(conn,username)
      if logging_in:

            stored_hash= logging_in[2]

            if passwordcheck(password,stored_hash):
                  return True
      return False

def send_verification_code(conn,username):
      import random 
      from datetime import datetime, timedelta

      st.session_state.verification_code = str(random.randint(100000,999999))
      st.session_state.code_expiry= datetime.now() + timedelta(minutes=1)

      import smtplib
      from email.message import EmailMessage
      

      email_sender= "coursework107@gmail.com"
      email_password ="tfly sjlb tqtx ponh"

      email_receiver = (get_mail(conn,username))
      msg = EmailMessage()
      msg['Subject']="Email Verification"
      msg['From']= email_sender
      msg['To']=email_receiver

      msg.set_content(f'Your verification code is: {st.session_state.verification_code}')

      with smtplib.SMTP_SSL("smtp.gmail.com",465) as smtp:
            smtp.login(email_sender,email_password)
            smtp.send_message(msg)    
      st.write('Email sent!')                                      

 
import streamlit as st

if 'logged_in' not in st.session_state:
      st.session_state.logged_in = False

if 'username' not in st.session_state:
      st.session_state.username = None

if 'pending_2fa' not in st.session_state:
      st.session_state.pending_2fa =  False


if not st.session_state.logged_in:

      st.title("🔐 User Authentication System")
      st.write("Please Login or Register")


if not st.session_state.logged_in and not st.session_state.pending_2fa:

      page = st.sidebar.selectbox(
      "Choose an option",
      ["Login", "Register"]
      )

      if page == 'Register':
            st.header('Create an Acccount')

            username= st.text_input("Username")
            email=st.text_input("Email")
            password=st.text_input("Create password",type="password")
            

            if st.button("Register"):
                  if register(username,password,email):
                        st.success("Account created!")
                  else:  st.error("Username already exists!")


      if page == "Login":
            st.header("Login🔑")

            username= st.text_input("Username")
            password=st.text_input("Password",type="password")

            if st.button("Login"):

                  if login(username,password):        
                         send_verification_code(conn,username)
                         print(username)
                         print(get_mail(conn,username))

                         st.session_state.pending_2fa = True                                                   
                         st.session_state.username=username
                         st.rerun()

                  else:  st.error("Incorrect Username or Password")


elif st.session_state.pending_2fa:
                  
      st.title("Please verify your email✅")
      entered_code=st.text_input("Please enter verification code")
      from datetime import datetime, timedelta
      st.session_state.code_expiry = datetime.now() + timedelta(minutes=1)

      if st.button('Verify'):

            if datetime.now() >= st.session_state.code_expiry:
                  st.error("Code expired")

            elif entered_code == st.session_state.verification_code:
                  st.session_state.logged_in = True
                  st.session_state.pending_2fa = False
                  st.rerun()

            else: 
                  st.error('Invalid or expired code')

      if st.button("Resend"):
            send_verification_code(conn,st.session_state.username)
            st.success("New code sent!")
                  
elif st.session_state.logged_in:

      page=st.sidebar.selectbox(
            "Dashboard",
            [
                  "Home",
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
      st.session_state.pending_2fa=False
      st.rerun()


from logic.cyber_incidents import get_all_incidents
from logic.it_tickets import get_all_tickets
from logic.metadatas import get_all_metadata

df=get_all_incidents()


if st.session_state.logged_in:

      st.title("🛡️ Security Intelligence Platform")

      st.markdown("""
      Welcome to the Security Intelligence Platform.
                  
      Use the sidebar to navigate between:
      -Cyber Incidents
      -IT Tickets
      -Metadata
      """)
      if page=='Cyber Incidents':
            st.title("Cyber Incidents🌐")

            overview_tab, data_tab, chart_tab, ai_tab= st.tabs(
            ['Overview','Data','Charts','AI']
      )
            

            with overview_tab:

                  st.subheader("Dataset overview")

                  st.info("""
                  Cyber Incidents Dataset Overview
                  This dataset contains records of cybersecurity incidents 
                  reported within an organization. Each record includes information such as the incident severity, 
                  category, status, timestamp, and a brief description. The dataset is used to monitor security events,
                  identify trends, and support incident management and response activities.""")
            with data_tab:
                  st.header("Data of incidents:")
                  st.dataframe(df)
                  
            with chart_tab:
                  st.header("Chart Analysis📈")
                  st.subheader("Status of Incidents:")
                  st.metric("Total Incidents", len(df))
                  st.metric("Resolved Incidents", len(df[df["status"]=="Resolved"]))
                  st.metric("In progress", len(df[df["status"]=="In Progress"]))
                  st.metric("Open Incidents", len(df[df["status"]=="Open"]))
                  st.metric("Closed Incidents", len(df[df["status"]=="Closed"]))

                  severity_count=df["severity"].value_counts()
                  st.subheader('Severity')
                  st.bar_chart(severity_count)

                  category_count= df["category"].value_counts()
                  st.subheader('Categories')
                  st.line_chart(category_count)


      elif page=='IT Tickets':
                  st.title("IT Tickets🌐")

                  overview_tab, data_tab, chart_tab, ai_tab= st.tabs(
                  ['Overview','Data','Charts','AI']
            )
                  

                  with overview_tab:

                        st.subheader("Dataset overview")

                        st.info("""
                        Cyber Incidents Dataset Overview
                        This dataset contains records of cybersecurity incidents 
                        reported within an organization. Each record includes information such as the incident severity, 
                        category, status, timestamp, and a brief description. The dataset is used to monitor security events,
                        identify trends, and support incident management and response activities.""")
                  with data_tab:
                        st.header("Data of incidents:")
                        st.dataframe(df)
                        
                  with chart_tab:
                        st.header("Chart Analysis📈")
                        st.subheader("Status of Incidents:")
                        st.metric("Total Incidents", len(df))
                        st.metric("Resolved Incidents", len(df[df["status"]=="Resolved"]))
                        st.metric("In progress", len(df[df["status"]=="In Progress"]))
                        st.metric("Open Incidents", len(df[df["status"]=="Open"]))
                        st.metric("Closed Incidents", len(df[df["status"]=="Closed"]))

                        severity_count=df["severity"].value_counts()
                        st.subheader('Severity')
                        st.bar_chart(severity_count)

                        category_count= df["category"].value_counts()
                        st.subheader('Categories')
                        st.line_chart(category_count)



# colour of UI 
st.html(
    """
    <style>
    [data-testid="stAppViewContainer"] {
        background-color: #002121;
    }
    [data-testid="stSidebar"] {
        background-color: #001010;
    }
    </style>
    """
)


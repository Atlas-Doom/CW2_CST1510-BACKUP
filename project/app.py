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
from app_model.users import   UI_colour
import pandas as pd
import streamlit as st
import plotly.express as px
from openai import OpenAI
from groq import Groq
from app_model.migrate import migrate
from app_model.db import profile_picture
import os
from app_model.db import update_pfp
from app_model.users import circular_image
from streamlit_cropper import st_cropper
from PIL import Image
from logic.cyber_incidents import get_all_incidents
from logic.it_tickets import get_all_tickets
from logic.metadatas import get_all_metadata


client = Groq(
      api_key=st.secrets['Open_AI_Key']
)

st.set_page_config (
      page_title="Security Intelligence Platform",
      page_icon='🛡️',
      layout="wide"
)

conn=get_connection()
create_user_table(conn)

def select_pw(conn):

    cursor = conn.cursor()
    cursor.execute("""
    SELECT password_hash FROM users WHERE username = ?
    """,
    (st.session_state.username,))
    pw= cursor.fetchone()
    if pw:
        return pw[0]
    else:
        return None


def passwordhash(password):
        pw_bytes= password.encode('utf-8')
        salt= bcrypt.gensalt()
        hashed_pw= bcrypt.hashpw(pw_bytes,salt)
        return hashed_pw

def change_pw(conn,new_pw):
    
    hashed=passwordhash(new_pw)
    cursor= conn.cursor()
    cursor.execute("""
    UPDATE users
    SET password_hash = ? WHERE username = ?
    """,
    (hashed,st.session_state.username,))
    conn.commit()

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

if 'profile' not in st.session_state:
      st.session_state.profile = None

if not st.session_state.logged_in:

      st.title("🔐 User Authentication System")
      st.write("Please Login or Register")


with st.sidebar:

      pfp_path= profile_picture(conn)
      if pfp_path and os.path.exists(pfp_path):
        circular_image(pfp_path)
      else:
        circular_image("Profile_Pictures/default pfp.jpg")


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
            confirm_pw= st.text_input("Confirm Password",type="password")
            
            if password == confirm_pw :
                  if st.button("Register"):
                        if register(username,password,email):
                              st.success("Account created!")
                        else:  st.error("Username already exists!")
            else:
                  st.error("Password don't match")

      if page == "Login":
            st.header("Login🔑")

            username= st.text_input("Username")
            password=st.text_input("Password",type="password")

            if st.button("Login"):
                  global user
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
      st.sidebar.write(f"Username-{st.session_state.username}")
      st.sidebar.divider()
      page=st.sidebar.selectbox(
            "Dashboard",
            [
                  "Home",
                  "Cyber Incidents",
                  "IT Tickets",
                  "Metadata",
                  "AI Chatbot",
                  "User Profile",
            ]
      )


# UI
st.sidebar.write('-------------------------')

if  st.sidebar.button('Logout ➜]'):

      st.session_state.logged_in=False
      st.session_state.username=None
      st.session_state.pending_2fa=False
      st.rerun()


if st.session_state.logged_in:
      

      if page == "Home":

            st.title("🛡️ Security Intelligence Platform")
            UI_colour("#0D1117","#161B22")
            st.subheader("""
            Welcome to the Security Intelligence Platform.
                        
            Use the sidebar to navigate between:\n
            ➤Cyber Incidents\n
            ➤IT Tickets\n
            ➤Metadata\n
            """)

            st.write('-------------------------')
            st.markdown(f"""
            # 🛡️ Welcome, {st.session_state.username}!

            Welcome to the **Security Intelligence Platform**, a centralized dashboard designed to support cybersecurity monitoring and operational analysis.

            Through this platform, you can:

            🔹 Explore Cyber Incident records and trends  
            🔹 Analyze IT Support Ticket performance  
            🔹 Review Dataset Metadata and statistics  
            🔹 Interact with the AI Assistant for insights and support  

            Use the navigation menu to access each module and begin exploring the data.
            """)
            st.write('-----')
            st.subheader("Brief Summary of each dashboard:")
            st.markdown('Cyber Incidents🌐')
            st.info("""
            This dataset contains records of cybersecurity incidents 
            reported within an organization. Each record includes information such as the incident severity, 
            category, status, timestamp, and a brief description. The dataset is used to monitor security events,
            identify trends, and support incident management and response activities.""")

            st.markdown('IT Tickets🎟️')     
            st.info("""
            This dataset contains records of IT support tickets submitted within the organization. 
            Each ticket includes information such as its priority level, current status, assigned technician, 
            creation date, and resolution time. The dataset is used to monitor support operations, track workload 
            distribution, identify ticket trends, and evaluate service efficiency.""")

            st.markdown("Metadata Dataset💾")
            st.info("""
                  Access detailed information about the datasets available within the platform. 
                  Review dataset characteristics, monitor data resources, and gain insights into the structure and management 
                  of organizational data assets.
                  """)


      if page=='Cyber Incidents':
            st.title("Cyber Incidents🌐")
            UI_colour("#2B0000","#121212")
            df=get_all_incidents()
            overview_tab, data_tab, chart_tab= st.tabs(
            ['Overview','Data','Charts']
            )

            with overview_tab:

                  st.subheader("Dataset overview")

                  st.info("""
                          The Cyber Incidents section displays all of the cybersecurity incidents that werereported within an organization
                          . The records include:\n
                          ❖ The Category of the incident\n
                          ❖ The Severity of each incident\n
                          ❖The Status of the incident\n
                          ❖ Brief Description and Timestamp\n
                          These datas can be utilised to monitor and keep track of incidents to improve the incident management services
                          .In addition, trends can be easily identified which allows organizations to find the most optimal approach to resolve 
                          the inquiries. """)

                  st.header("Quick Summary:")
                  st.subheader("Status of Incidents:")
                  
                  with st.container(border=True):

                        col1, col2, col3, col4, col5= st.columns(5)
                        
                        with col1:
                              st.metric("Total Incidents", len(df))
                        with col2:
                              st.metric("⏳ In progress", len(df[df["status"]=="In Progress"]))
                        with col3:
                              st.metric("🔓 Open Incidents", len(df[df["status"]=="Open"]))
                        with col4:
                              st.metric("🔒 Closed Incidents", len(df[df["status"]=="Closed"]))
                        with col5:
                              st.metric("✅ Resolved Incidents", len(df[df["status"]=="Resolved"]))
                  
                  st.subheader("💡 Key Insights")
                  most_common = df["severity"].mode()[0]

                  st.warning(f"Most common severity level⚠️: {most_common}")
                  st.warning(f"Number of Open cases🔓: {len(df[df["status"]=="Open"])}")

            with data_tab:
                  st.header("Data of incidents:")
                  st.dataframe(df)
                  
            with chart_tab:
                  st.header("Chart Analysis📈")
                  st.subheader("Status of Incidents📊:")
                  
                  cross_tab = pd.crosstab(
                  df["severity"],
                  df["status"]
                  )

                  fig= px.bar(
                        cross_tab,
                        barmode="group",     
                  )

                  st.plotly_chart(fig)


                  st.subheader("Category of Incidents🗂️:")

                  selected_severity= st.multiselect(
                        "Select Severity",
                        df["severity"].unique(),
                        default =df['severity'].unique(),
                  )
                  filtered= df[df["severity"].isin(selected_severity)]
                  severity_trend = pd.crosstab(
                        filtered["severity"],
                        filtered["category"]
                  )
                  st.line_chart(severity_trend)


      elif page=='IT Tickets':
                  st.title("IT Tickets🎟️")
                  UI_colour("#002121","#001010")
                  df=get_all_tickets()
                  overview_tab, data_tab, chart_tab= st.tabs(
                  ['Overview','Data','Charts']
            )
                  

                  with overview_tab:
                        st.subheader("Dataset overview")

                        st.info("""
                        This dataset contains records of IT support tickets submitted within the organization. 
                        Each ticket includes information such as its priority level, current status, assigned technician, 
                        creation date, and resolution time. The dataset is used to monitor support operations, track ticket workloads, 
                        identify service trends, and evaluate support team performance. The records include:\n
                        ❀Ticket priority\n
                        ❀Current Status\n
                        ❀Assigned Technician\n
                        ❀Creation Date and Time(Hours)\n
                        ❀Resolution Time\n
                        ❀Ticket Description\n
                        This dashboard provides insights into IT support operations by visualizing ticket priorities, statuses, 
                        technician workloads, and resolution performance. It helps identify trends, monitor service efficiency, 
                        and support operational decision-making.
                        """)
                        st.header("Quick Summary:")
                        st.subheader("Status of Incidents:")

                        with st.container(border=True):
                              col1, col2, col3, col4=st.columns(4)
                              with col1:
                                    st.metric("Total Incidents", len(df))
                              with col2:
                                    st.metric("Resolved Incidents", len(df[df["status"]=="Resolved"]))
                              with col3:
                                    st.metric("In progress", len(df[df["status"]=="In Progress"]))
                              with col4:
                                    st.metric("Open Incidents", len(df[df["status"]=="Open"]))

                        st.subheader("💡 Key Insights")
                        most_common = df["priority"].mode()[0]

                        st.warning(f"Most common priority level⚠️: {most_common}")
                        st.warning(f"Number of Open cases🔓: {len(df[df["status"]=="Open"])}")

                  with data_tab:
                        st.header("Data of IT Tickets:")
                        st.dataframe(df)
                        
                  with chart_tab:

                        st.subheader("Status since Creation🛠️:")
                        df["created_at"] = pd.to_datetime(df["created_at"])
                        priority_trend = (
                        df.groupby(
                              [df["created_at"].dt.strftime("%Y-%m"), "status"]
                        )
                        .size()
                        .unstack(fill_value=0)
                        )
                        
                        st.line_chart(priority_trend)

                        st.subheader("Technicians Assigned👨🏻‍💻:")
                        selected_status=st.multiselect(
                              "Select Status",
                              df["status"].unique(),
                              default= df["status"].unique(),
                        )
                        filtered_IT=df[df['status'].isin(selected_status)]
                        status_trend=pd.crosstab(
                              filtered_IT["status"],
                              filtered_IT["assigned_to"]
                        )
                        st.scatter_chart(status_trend)


      elif page=="Metadata":
            df=get_all_metadata()
            st.title("Metadata💾")
            UI_colour('#17153B',"#030830")
            overview_tab, data_tab, chart_tab= st.tabs(
                  ['Overview','Data','Charts']
            )

            with data_tab:
                  st.header('Data of Metadata:')
                  st.dataframe(df)
            
            with overview_tab:
                  st.info('''
                  The Datasets Metadata section provides summary information about the datasets 
                  stored within the platform. It includes details such as dataset names, record counts, number of columns, upload 
                  dates, and the users responsible for uploading them. This information helps administrators manage data resources,
                  monitor dataset growth, and maintain an organized repository of information assets. The record includes:\n
                  ✽ Dataset ID\n
                  ✽ Dataset Name\n
                  ✽ Number of Rows\n
                  ✽ Number of Columns\n
                  ✽ Uploaded By\n
                  ✽ Upload Date\n
                  ''')
                  st.header("Quick Summary:")
                  st.subheader("Uploaders:")
                  with st.container(border=True):
                        col1, col2, col3, col4=st.columns(4)

                        with col1:
                              st.metric("Number of Uploads",len(df))
                        with col2:
                              st.metric("Data Scientist",len(df[df["uploaded_by"]=="data_scientist"]))
                        with col3:
                              st.metric("Cyber Admin",len(df[df["uploaded_by"]=="cyber_admin"]))
                        with col4:
                              st.metric("IT Admin",len(df[df["uploaded_by"]=="it_admin"]))
            with chart_tab:

                        st.subheader("Number of rows and columns per dataset:")                  
                        select_name=st.multiselect(
                              "Select Dataset:",
                              df["name"].unique(),
                              default=df["name"].unique(),

                        )
                        filtered_data=df[df['name'].isin(select_name)]
                        fig=px.bar(
                              filtered_data,
                              x="name",
                              y=["rows","columns"],
                              barmode="group",
                        )
                        st.plotly_chart(fig)
      
      elif page == "AI Chatbot":
            UI_colour('#0C0950','#090040')
            st.title("👾 AI Security Assistant")
            Cyber_incidents, it_tickets, Metadata=st.tabs(
                  ["Cyber Incidents","IT Tickets","Metadata" ]
            )

            with Cyber_incidents:
                  
                  cyber_prompt="""You are a senior cybersecurity analyst. Analyse incidents using MITRE ATT&CK and CVE references. 
                  Provide structured responses: Root Cause, Immediate Actions, Prevention Measures, Risk Level."""

                  if 'cyber_messagers' not in st.session_state:
                        st.session_state.cyber_messagers=[
                              {
                                    'role':'system',
                                    "content" : cyber_prompt
                              }
                        ]
                  st.subheader("🛡️ Cybersecurity Assistant")
                  for message in st.session_state.cyber_messagers:
                        if message["role"] != 'system':
                              with st.chat_message(message['role']):
                                    st.write(message['content']) 
            
                  question= st.chat_input("Ask a cybersecurity question...")               

                  if question:

                        with st.chat_message("user"):
                              st.write(question)

                        st.session_state.cyber_messagers.append(
                              {
                                    'role':"user",
                                    "content":question
                              }
                        )
                        response = client.chat.completions.create(
                                    model="openai/gpt-oss-120b",
                                    messages=st.session_state.cyber_messagers
                        )
                        answer=response.choices[0].message.content
                        with st.chat_message("assistant"):
                              st.write(answer)
                              
                        st.session_state.cyber_messagers.append(
                              {
                                    'role':"assistant",
                                    "content":answer
                              }
                        )
                  if st.button("New Chat",key="cyber_new"):
                        st.session_state.cyber_messagers = [
                        {
                              "role": "system",
                              "content": cyber_prompt
                        }
                        ]
                        st.rerun()
                        
            with it_tickets:
                  st.subheader("💻 IT Operations Assistant")

                  it_ticket_prompt="You are an IT operations lead. Prioritise support tickets by impact and urgency, suggest troubleshooting steps and provide infrastructure best practices."
                  if 'it_messagers' not in st.session_state:
                        st.session_state.it_messagers=[
                              {
                                    'role':'system',
                                    "content" : it_ticket_prompt
                              }
                        ]
                  for message in st.session_state.it_messagers:
                        if message["role"] != 'system':
                              with st.chat_message(message['role']):
                                    st.write(message['content']) 
            
                  question= st.chat_input("Ask an IT support question...")        

                  if question:

                        with st.chat_message("user"):
                              st.write(question)

                        st.session_state.it_messagers.append(
                              {
                                    'role':"user",
                                    "content":question
                              }
                        )
                        response = client.chat.completions.create(
                                    model="openai/gpt-oss-120b",
                                    messages=st.session_state.it_messagers
                        )
                        answer=response.choices[0].message.content
                        with st.chat_message("assistant"):
                              st.write(answer)
                              
                        st.session_state.it_messagers.append(
                              {
                                    'role':"assistant",
                                    "content":answer
                              }
                        )
                  if st.button("New Chat",key="IT_new"):
                        st.session_state.it_messagers = [
                        {
                              "role": "system",
                              "content": it_ticket_prompt
                        }
                        ]
                        st.rerun()

            
            with Metadata:
                  st.subheader("📊 Data Science Assistant")
                  question= st.chat_input("Ask a data science question...")
                  data_science_prompt="You are a data science expert. Help with dataset analysis, choosing visualisation types, statistical methods and machine learning. Suggest concrete next steps."
                  if 'meta' not in st.session_state:
                        st.session_state.meta=[
                              {
                                    'role':'system',
                                    "content" : data_science_prompt
                              }
                        ]
                  for message in st.session_state.meta:
                        if message["role"] != 'system':
                              with st.chat_message(message['role']):
                                    st.write(message['content'])     

                  if question:

                        with st.chat_message("user"):
                              st.write(question)

                        st.session_state.meta.append(
                              {
                                    'role':"user",
                                    "content":question
                              }
                        )
                        response = client.chat.completions.create(
                                    model="openai/gpt-oss-120b",
                                    messages=st.session_state.meta
                        )
                        answer=response.choices[0].message.content
                        with st.chat_message("assistant"):
                              st.write(answer)
                              
                        st.session_state.meta.append(
                              {
                                    'role':"assistant",
                                    "content":answer
                              }
                        )
                  if st.button("New Chat",key="Meta_new"):
                        st.session_state.meta = [
                        {
                              "role": "system",
                              "content": data_science_prompt
                        }
                        ]
                        st.rerun()


      elif page == "User Profile":
            st.title("User Profile") 

            pfp_path = profile_picture(conn)

            if pfp_path:
                  circular_image(pfp_path)
            else:
                  circular_image("Profile_Pictures/default pfp.jpg")
                  
            col1, col2= st.columns(2)
            with col1:
                  uploaded_file = st.file_uploader(
                  "Choose a profile picture",
                  type=["png", "jpg", "jpeg"]
                  )

            if uploaded_file is not None:
                  
                  if st.button("Save Profile Picture"):


                        os.makedirs("Profile_Pictures", exist_ok=True)

                        filename = f"Profile_Pictures/{st.session_state.username}.png"

                        with open(filename, "wb") as f:
                              f.write(uploaded_file.getbuffer())

                        st.success("Profile picture uploaded!")  

                        update_pfp(conn,filename)
                        st.rerun()

            st.subheader("User Info")
            st.divider()
            st.write(f"Username: {st.session_state.username}")  
            with st.expander("Change Username"):

                  New_name=st.text_input("Enter New Username")

                  if st.button("Save New Username"):
                        if New_name.strip() == "":
                              st.error("Username cannot be empty")
                        else:
                              update_user(conn,st.session_state.username,New_name)
                              st.session_state.username = New_name
                              st.success("Username successfully updated!")
                              st.rerun()



            email_ = get_mail(conn,st.session_state.username)
            st.write(f"Email Address: {email_}")

            with st.expander("Change Password"):

                  new_password = st.text_input(
                        "Enter New Password",
                        type="password"
                  )

                  if st.button("Confirm Password"):

                        if new_password.strip() == "":
                              st.error("Please enter a password.")

                        else:
                              change_pw(conn, new_password)
                              st.success("Password changed successfully!")
                              st.rerun()

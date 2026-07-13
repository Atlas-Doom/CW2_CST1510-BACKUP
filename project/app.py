import os
import re
import bcrypt
import smtplib
import pandas as pd
from groq import Groq
import streamlit as st
from openai import OpenAI
import plotly.express as px
from email.message import EmailMessage
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
from app_model.migrate import migrate
from app_model.db import profile_picture
from app_model.db import update_pfp
from app_model.users import circular_image
from logic.cyber_incidents import get_all_incidents
from logic.it_tickets import get_all_tickets
from logic.metadatas import get_all_metadata
from app_model.users import get_username
from datetime import datetime, timedelta

client = Groq(
      api_key=st.secrets['Groq_AI_Key']    # API for AI including AI key that was kept hidden using secrets
)

st.set_page_config (
      page_title="Security Intelligence Platform",
      page_icon='🛡️',
      layout="wide"
)   # Title for the page of the web app. (name that is displayed on the tab)

conn=get_connection()    # Connects conn to the database
create_user_table(conn) # This creates the database if it does not already exist 

def passwordhash(password):       # This function converts the password first then adds a randomly generated salt to it
      pw_bytes= password.encode('utf-8') 
      salt= bcrypt.gensalt()
      hashed_pw= bcrypt.hashpw(pw_bytes,salt) # And this hashes the password alongside the salt
      return hashed_pw

def passwordcheck(password,hashed_pw):   
      password_byte=password.encode("utf-8")
      return bcrypt.checkpw(password_byte,hashed_pw) # compares the password stored in the database to the password the user inputted     

def change_pw(conn,new_pw):       # Function that changes the password in the database where the username is given
      hashed=passwordhash(new_pw)
      cursor= conn.cursor()
      cursor.execute("""
      UPDATE users
      SET password_hash = ? WHERE username = ?
      """,
      (hashed,st.session_state.username,)) # this is the username that has been stored in this session state 
      conn.commit()                       # which is used in the changing password feature on the user profile page 

def update_pw(conn,new_pw):    #This function has the exact same purpose as the previous one however this one is used only on the login page for the forgot password feature
      hashed=passwordhash(new_pw)
      cursor= conn.cursor()
      cursor.execute("""
      UPDATE users
      SET password_hash = ? WHERE username = ?
      """,
      (hashed,st.session_state.reset_username,))# session state used specifically for storing the username of the user 
                                                # on the changing password page on the login


def select_pw(conn):    # This 
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

def register(username,password,email):   #Takes data from the users which will be used to create their account
      username_exists = get_user(conn,username)   # if the username already exists it will go fetch that username in the database
      if username_exists:      # If it exists the function will stop
            return False
                        
      hashed_password=passwordhash(password)
      add_user(conn,username,hashed_password,email) #else it will just add the user to the database meaning that the acc was created
      return True

def login(username,password):  
      
      logging_in= get_user(conn,username) #finds the user with inputted username
      if logging_in:

            stored_hash= logging_in[2]     #if true its going to store the password of the user inside the stored_hash

            if passwordcheck(password,stored_hash):  # and compare it using the previous function
                  return True
      return False

def send_verification_code(conn,username):   # Function used for 2FA and verification for changing passwords
      import random 
      from datetime import datetime, timedelta

      st.session_state.verification_code = str(random.randint(100000,999999))  # randomly generated 6 digit code
      st.session_state.code_expiry= datetime.now() + timedelta(minutes=1)  #used for the expiry time of the 6 digit code

      email_sender= "coursework107@gmail.com"  # email of the acc thats sending the code
      email_password ="tfly sjlb tqtx ponh"  # account api key

      email_receiver = (get_mail(conn,username))    # using the getmail function we are fetching the email of the user
      msg = EmailMessage()
      msg['Subject']="Email Verification"
      msg['From']= email_sender
      msg['To']=email_receiver

      msg.set_content(f'Your verification code is: {st.session_state.verification_code}')  # content of the mail

      with smtplib.SMTP_SSL("smtp.gmail.com",465) as smtp:   #using smtp we can send the user the email
            smtp.login(email_sender,email_password)
            smtp.send_message(msg)    
      st.write('Email sent!')                            


def display_check_pw(requirements,sentence):   # this is used for checking the password strength when the user is creating his account
      if requirements:
            st.markdown(f'✅,{sentence}')
      else: 
            st.markdown(f"❌ <span style='color:gray'>{sentence}</span>", unsafe_allow_html=True)          

if 'logged_in' not in st.session_state:       # Using several session states we can keep track of the acitvity of the user
      st.session_state.logged_in = False
if 'username' not in st.session_state:  # stores username in the session state
      st.session_state.username = None
if 'pending_2fa' not in st.session_state:  # session state for 2FA
      st.session_state.pending_2fa =  False
if 'profile' not in st.session_state:  # Session state for the user profile
      st.session_state.profile = None
if "forgot_pw" not in st.session_state:  # session state for the forgot password page
      st.session_state.forgot_pw = False
if "change_pw" not in st.session_state:  # Session state to change password page on the login page
      st.session_state.change_pw = False
if "send_code" not in st.session_state:  # Session state for verification code for forgot password
      st.session_state.send_code = False

if not st.session_state.logged_in:              #This is what the user sees first when opening the webapp. 
      st.title("🔐 User Authentication System")
      st.write("Please Login or Register")


with st.sidebar:              # sidebar profile picture displayed using a previously created function that helps to display the pfp in the traditional circular shape
      pfp_path= profile_picture(conn)
      if pfp_path and os.path.exists(pfp_path):
            circular_image(pfp_path)
      else:
            circular_image("Profile_Pictures/default pfp.jpg")


if not st.session_state.logged_in and not st.session_state.pending_2fa:

      page = st.sidebar.selectbox(
      "Choose an option",
      ["Login", "Register"]
      )      # using selectbox to allow user to choose between Login or Register

      if page == 'Register':
            
            st.header('Create an Acccount')

            username= st.text_input("Username")  #Text input for username
            email=st.text_input("Email") # email input
            password=st.text_input("Create password",type="password")  #password input
            st.write('🔒 Password Strength Meter')
            if password:  
                  length_pw= len(password) >= 12
                  caps_pw=bool( re.search(r'[A-Z]',password )) # at least one capital letter
                  lowcaps_pw= bool(re.search(r'[a-z]',password)) # at least one low caps letter
                  digits_pw= bool(re.search(r'[0-9]',password))  # at least one number
                  special_pw= bool(re.search(r'[^A-Za-z0-9]',password)) # at least one special character

                  score = sum([length_pw,caps_pw,lowcaps_pw,digits_pw,special_pw]) # If each of the criteria is met its going to add to the score
                  progress_percentage= score/5  # this creates a progression percentage to track the strength of the password

                  display_check_pw(length_pw, "At least 12 characters long")
                  display_check_pw(caps_pw, "Contains uppercase letters (A-Z)")
                  display_check_pw(lowcaps_pw, "Contains lowercase letters (a-z)")   # creates a checklist for the password requirements
                  display_check_pw(digits_pw, "Contains at least one number (0-9)")
                  display_check_pw(special_pw, "Contains at least one special character (e.g., !, @, #, $)")
                  
                  if score <= 2:   # if the score of the password is below 2 or equal to 2 it will print weak password whilst showing the progression of the score
                        st.error("Weak Password ❌")
                        st.progress(progress_percentage)
                  elif score <=4: #Progression will keep on progressing but the score if is below 4 or 4 its still going to be of moderate strength
                        st.warning("Moderate Strength ⚠️")
                        st.progress(progress_percentage)
                  else:
                        st.success("Strong Password✅!")  # if the score is 5 which is the max its going to be then the user can finally register
                  
                        confirm_pw= st.text_input("Confirm Password",type="password")
                        
                        if password == confirm_pw :  # When both passwords match, the register button will appear 
                              if st.button("Register"):
                                    if register(username,password,email):
                                          st.success("Account created!")
                                    else:  st.error("Username already exists!")
                        elif confirm_pw:
                              if password != confirm_pw:  
                                    st.error("Password don't match")


      if page == "Login" and st.session_state.forgot_pw == False and st.session_state.change_pw== False:
            st.header("Login🔑")

            username= st.text_input("Username")  #  
            password= st.text_input("Password",type="password")

            if st.button("Login"):
                  global user   # global variable 
                  if login(username,password):   # Login function to check if the username and the password of the user match
                        send_verification_code(conn,username)  # send verification for the 2FA
                        st.session_state.pending_2fa = True  # Session state to switch the page for 2FA                                   
                        st.session_state.username=username  # stores the username of the user in this session state
                        st.rerun()

                  else:  st.error("Incorrect Username or Password")
            elif st.button("Forgot Password?"): 
                  st.session_state.forgot_pw = True   # if the user presses the forgot password button the session state will become true and the page will change
                  st.rerun()

      elif  page=="Login" and st.session_state.forgot_pw == True and st.session_state.send_code== False: # if all requirements are met the page will change to the change password

            st.title('Change Password')
            email=st.text_input("Enter email address")
            if st.button("Send Verification code ✉"):   
                  username=get_username(conn,email)   # search for username via the email 
                  if username:
                        send_verification_code(conn,username) # send code to the user
                        st.session_state.send_code =True
                        st.session_state.forgot_pw = True
                        st.session_state.code_expiry = datetime.now() + timedelta(minutes=1)  # expiry of 1 min of the verification code
                        st.session_state.reset_username = username  # stores username in the reset username session state
                        st.rerun()
                  else:
                        st.error('Account related to email has not been found.')  # username not found in database

      elif page == "Login" and st.session_state.send_code == True and st.session_state.forgot_pw == True : # Change page for the verification code
            st.write('Please Verify email before proceeding✅')
            input_code=st.text_input("Enter Verification code")

            if st.button('Verify'):

                  if datetime.now() >= st.session_state.code_expiry:
                        st.error("Code expired")

                  elif  input_code == st.session_state.verification_code:  # if input code matches the verification code then session state will change
                        st.session_state.forgot_pw = False
                        st.session_state.change_pw = True
                        st.session_state.send_code = False
                        st.rerun()

                  else: 
                        st.error('Invalid or expired code')  

            if st.button("Resend"):  # resend verification code and reset expiry time
                  send_verification_code(conn,st.session_state.reset_username)
                  st.session_state.code_expiry = datetime.now() + timedelta(minutes=1)
                  st.success("New code sent!") 

      elif st.session_state.change_pw == True : # changes page to change password page

            st.title("Change Password🔄")
            new_pw=st.text_input("Please enter new password",type='password')
            confirm_pw = st.text_input("Confirm New Password", type="password")

            if st.button("Confirm Password"):
                  if new_pw != confirm_pw:
                        st.error("Passwords do not match.")
                  else:
                        if new_pw.strip() == "":
                              st.error("Please enter a password.")
                        else:
                              update_pw(conn, new_pw)  # function that updates the password of the user using the reset password session state
                              st.success("Password changed successfully!")
                              st.session_state.change_pw = False  
                              st.session_state.forgot_pw = False
                              st.session_state.send_code = False
                              st.rerun()

elif st.session_state.pending_2fa:  #2FA page after login page
                  
      st.title("Please verify your email✅")
      entered_code=st.text_input("Please enter verification code")
      from datetime import datetime, timedelta  # concept exactly the same as verification code one 
      st.session_state.code_expiry = datetime.now() + timedelta(minutes=1)

      if st.button('Verify'):

            if datetime.now() >= st.session_state.code_expiry: 
                  st.error("Code expired")

            elif entered_code == st.session_state.verification_code:
                  st.session_state.logged_in = True
                  st.session_state.pending_2fa = False
                  st.rerun()

            else: 
                  st.error('Invalid or expired code') # wrong code will show this message

      if st.button("Resend"):  # resends the code
            send_verification_code(conn,st.session_state.username)
            st.success("New code sent!")

# UI
elif st.session_state.logged_in:
      st.sidebar.write(f"Username-{st.session_state.username}")
      st.sidebar.divider()
      page=st.sidebar.selectbox(    # creates selectbox in the sidebar for user to choose between different pages 
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
st.sidebar.divider() # creates divider

if  st.sidebar.button('Logout ➜]'):

      st.session_state.logged_in=False
      st.session_state.username=None
      st.session_state.pending_2fa=False
      st.session_state.forgot_pw = False
      st.session_state.change_pw = False   # all session state are reset which returns the web app back to the login page
      st.rerun()

if st.session_state.logged_in:  
      if page == "Home":

            st.title("🛡️ Security Intelligence Platform")
            UI_colour("#0D1117","#161B22") # Function created to change the colour of the page
            st.subheader("""
            Welcome to the Security Intelligence Platform.
            Use the sidebar to navigate between:\n
            ➤Cyber Incidents\n
            ➤IT Tickets\n
            ➤Metadata\n
            """)  # info about how to access other pages

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
            """)  # gives some info on the use of the web app 
            st.write('-----')
            st.subheader("Brief Summary of each dashboard:")
            st.markdown('Cyber Incidents🌐')
            st.info("""
            This dataset contains records of cybersecurity incidents 
            reported within an organization. Each record includes information such as the incident severity, 
            category, status, timestamp, and a brief description. The dataset is used to monitor security events,
            identify trends, and support incident management and response activities.""")
            # gives info about each of the 3 datasets and what they can expect on the page
            st.markdown('IT Tickets🎟️')     
            st.info("""
            This dataset contains records of IT support tickets submitted within the organization. 
            Each ticket includes information such as its priority level, current status, assigned technician, 
            creation date, and resolution time. The dataset is used to monitor support operations, track workload 
            distribution, identify ticket trends, and evaluate service efficiency.""")
            # gives info about each of the 3 datasets and what they can expect on the page
            st.markdown("Metadata Dataset💾")
            st.info("""
            Access detailed information about the datasets available within the platform. 
            Review dataset characteristics, monitor data resources, and gain insights into the structure and management 
            of organizational data assets.
            """)
            # gives info about each of the 3 datasets and what they can expect on the page

      if page=='Cyber Incidents':  # cyber page 
            st.title("Cyber Incidents🌐")
            UI_colour("#2B0000","#121212") # use function to change the colour of the UI
            df=get_all_incidents()
            overview_tab, data_tab, chart_tab= st.tabs(
            ['Overview','Data','Charts']
            )  #3 tabs that will be used to allow user to access different function on that page 

            with overview_tab:
                  st.subheader("Dataset overview")
                  # Overview  tab gives the user an idea of what lies inside this page, and what the dataset contains
                  st.info("""
                  The Cyber Incidents section displays all of the cybersecurity incidents that werereported within an organization
                  . The records include:\n
                  ❖ The Category of the incident\n
                  ❖ The Severity of each incident\n
                  ❖The Status of the incident\n
                  ❖ Brief Description and Timestamp\n
                  These datas can be utilised to monitor and keep track of incidents to improve the incident management services
                  In addition, trends can be easily identified which allows organizations to find the most optimal approach to resolve 
                  the inquiries. """)

                  st.header("Quick Summary:")
                  st.subheader("Status of Incidents:")
                  
                  with st.container(border=True):  # quick insight of some key data in the file

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
                  # data tab contains the dataframe in the page alongside filtering
                  st.header("Data of incidents:")

                  df2 = get_all_incidents()

                  severity = st.selectbox("Severity",['All'] + list(df2['severity'].unique()))# filtering per severity
                  if severity != "All":
                        df2= df2[df2['severity']==severity]
                  col1 , col2 = st.columns(2)
                  with col1:
                        category = st.radio("Category", ["All"]+ list(df2["category"].unique()))# all filtering per categories
                        if category != "All":
                              df2 = df2[df2['category']==category]
                  with col2:
                        status = st.radio("Status", ["All"]+ list(df2["status"].unique())) # filtering per status
                        if status != "All":
                              df2 = df2[df2['status']== status]

                  st.dataframe(df2)

            with chart_tab:
                  # the chart tab is used to display charts to compare the data of the file allowing user to view and have a better understanding of the dataframe
                  st.header("Chart Analysis📈")
                  st.subheader("Status of Incidents📊:")
                  
                  cross_tab = pd.crosstab(
                  df["severity"],
                  df["status"]
                  )

                  fig= px.bar(  # using plotly to create the chart
                        cross_tab,
                        barmode="group", 
                        labels={
                              "value": "Number of Incidents",
                              "severity": "Severity"
                        },
                        title="Cyber Incidents by Severity and Status",
                        template="plotly"   # colour of the chart chosen by plotly itself
                        )


                  st.plotly_chart(fig)

                  img_bytes = fig.to_image(format="pdf")
                  st.download_button(
                  label="📥 Export Chart",
                  data=img_bytes,
                  file_name="Cyber_Incident.pdf",
                  mime="file/pdf"
                  )  # export feature which has been set to PDF for this specific chart with the varible name fig
            
                  st.subheader("Category of Incidents🗂️:")

                  selected_severity= st.multiselect(  # multiselect option to allow user to filter the chart per severity
                        "Select Severity",
                        df["severity"].unique(),
                        default =df['severity'].unique(),
                  )
                  filtered= df[df["severity"].isin(selected_severity)]
                  severity_trend = pd.crosstab(
                        filtered["severity"],
                        filtered["category"]
                  )

                  fig2= px.line(
                        severity_trend,
                        labels={
                              "category":"Category of Incident",
                              "severity": "Severity"
                        },
                        title= "Category of each incident V/S their Severity",
                        template="plotly",
                  )           # line chart created using plotly
                  
                  st.plotly_chart(fig2)

                  img_bytes2 = fig2.to_image(format="pdf")
                  st.download_button(
                  label="📥 Export Chart",
                  data=img_bytes2,
                  file_name="Cyber_Incidents_Categories.pdf",
                  mime= "file/pdf",
                  )# export feature which has been set to PDF for this specific chart with the varible name fig2

      elif page=='IT Tickets':
                  
                  st.title("IT Tickets🎟️")
                  UI_colour("#002121","#001010") # UI function to change the color of the IT tickets tab
                  df=get_all_tickets() # function to call the dataset IT tickets to the variable df
                  overview_tab, data_tab, chart_tab= st.tabs(
                  ['Overview','Data','Charts']
            )#3 tabs that will be used to allow user to access different function on that page 
                  

                  with overview_tab:
                        st.subheader("Dataset overview")
                        # This provides a summary of the dataset prevent in the file 
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
                                    st.metric("Open Incidents", len(df[df["status"]=="Open"])) # few quick insights

                        st.subheader("💡 Key Insights")
                        most_common = df["priority"].mode()[0]

                        st.warning(f"Most common priority level⚠️: {most_common}")
                        st.warning(f"Number of Open cases🔓: {len(df[df["status"]=="Open"])}")

                  with data_tab:
                        df2=get_all_tickets() # used different variable name to prevent other charts to be altered whilst filtering the main dataset
                        st.header("Data of IT Tickets:")

                        priority= st.selectbox("Priority",["All"] + list(df2["priority"].unique()))
                        if priority != "All": # filtering per priority
                              df2= df2[df2['priority'] == priority]

                        col1, col2 = st.columns(2)

                        with col1:
                              status = st.radio('Status',['All'] + list(df2['status'].unique()))
                              if status != "All":
                                    df2=df2[df2['status']== status] # filtering per status
                        with col2:
                              assigned = st.radio('Assigned To',['All'] + list(df2['assigned_to'].unique()))
                              if assigned != "All":
                                    df2=df2[df2['assigned_to']==assigned] # filtering per assigned IT supports

                        st.dataframe(df2)                        
                  with chart_tab:

                        st.subheader("Status since Creation🛠️:")
                        df["created_at"] = pd.to_datetime(df["created_at"]) #
                        priority_trend = (
                        df.groupby(
                              [df["created_at"].dt.strftime("%Y-%m"), "status"]
                        )
                        .size()
                        .unstack(fill_value=0)
                        )
                        fig= px.line(
                              priority_trend,
                              x=priority_trend.index,
                              y=priority_trend.columns,
                              markers=True,
                              template="plotly", # line chart created using plotly

                        )
                        st.plotly_chart(fig)

                        img_bytes = fig.to_image(format="pdf")

                        st.download_button(
                              label="📥 Export Chart",
                              data=img_bytes,
                              file_name="IT_Tickets_Creation_Date",
                              mime="file/pdf"
                        ) # exporting feature set to pdf for the specific chart by the variable fig 

                        st.subheader("Technicians Assigned👨🏻‍💻:") # multiselect option to allow  user to fitler the scatter chart per technicians
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

                        fig2 = px.scatter(
                              status_trend,
                              template="plotly",
                        ) # scatter chart using plotly

                        st.plotly_chart(fig2)

                        img_bytes2= fig2.to_image(format="pdf")
                        st.download_button(
                              label="📥 Export Chart",
                              data= img_bytes2,
                              file_name="IT_Tickets_assigned",
                              mime="file/pdf",
                        ) # export chart feature using variable Fig 2 in pdf format
                        
      elif page=="Metadata":

            st.title("Metadata💾")
            df=get_all_metadata()
            UI_colour('#17153B',"#030830")# change UI color for metadata page
            overview_tab, data_tab, chart_tab= st.tabs(
                  ['Overview','Data','Charts']
            ) #3 tabs that will be used to allow user to access different function on that page 

            with overview_tab:
                  # Gives user an overview/sumamry of what to expect on this dataset
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
                              st.metric("IT Admin",len(df[df["uploaded_by"]=="it_admin"])) # quick insights
            with data_tab:
                  # shows the dataset of metadata 
                  st.header('Data of Metadata:')
                  df2= get_all_metadata()
                  uploaded = st.selectbox("Uploaded by", ["All"] + list(df2["uploaded_by"].unique()))
                  if uploaded != "All": # filtering by who uploaded the data
                        df2 = df2[df2["uploaded_by"] == uploaded]
                  
                  st.dataframe(df2)
            
            with chart_tab:

                        st.subheader("Number of rows and columns per dataset:")                  
                        select_name=st.multiselect(
                              "Select Dataset:",
                              df["name"].unique(),
                              default=df["name"].unique(),  # this creates a multiselect option to allow user to filter chart in 
                              #order to see how many rows and columns per dataset uploaded by that person
                        )
                        filtered_data=df[df['name'].isin(select_name)]
                        fig=px.bar(
                              filtered_data,
                              x="name",
                              y=["rows","columns"],
                              barmode="group",
                        )# bar chart made using plotly
                        st.plotly_chart(fig)

                        img_bytes = fig.to_image(format="pdf")
                        st.download_button(
                        label="📥 Export Chart",
                        data=img_bytes,
                        file_name="Metadata.pdf",
                        mime="file/pdf"
                        )# download for bar chart in pdf format
                        
      elif page == "AI Chatbot":  # AI Chatbot page
            UI_colour('#0C0950','#090040') # UI colour changed
            st.title("👾 AI Security Assistant")
            Cyber_incidents, it_tickets, Metadata=st.tabs(
                  ["Cyber Incidents","IT Tickets","Metadata" ]
            ) # each tab represent an AI assistant for each specific sector

            with Cyber_incidents:
                  # the prompt for the cyber incidents assistant
                  cyber_prompt="""You are a senior cybersecurity analyst. 
                  You must ONLY answer questions related to cybersecurity, cyber incidents,
                  network security, malware, digital forensics, penetration testing,
                  vulnerabilities, MITRE ATT&CK, CVEs, and information security.
                  Analyse incidents using MITRE ATT&CK and CVE references. 
                  Provide structured responses: Root Cause, Immediate Actions, Prevention Measures, Risk Level.
                  If the users questions does not correlate with Cyber security or help Cyber incidents etc.. politely respond with:
                  I am sorry I do not understand. I was designed to asssit you regarding cybersecurity and cyber incidents. Please ask a 
                  question related to Cybersecurity and Cyber Incidents and I'll be happy to assist you!"""

                  if 'cyber_messagers' not in st.session_state:
                        st.session_state.cyber_messagers=[ # this basically stores the messagers inside of the session state to prevent the AI from forgetting what has been said previously
                              {
                                    'role':'system', # the role assigned here is the system which is storing the cyber prompt
                                    "content" : cyber_prompt
                              }
                        ]
                  st.subheader("🛡️ Cybersecurity Assistant")
                  for message in st.session_state.cyber_messagers:
                        if message["role"] != 'system': 
                              with st.chat_message(message['role']): # icon 
                                    st.write(message['content'])  # writes every msg that has been typed
            
                  question= st.chat_input("Ask a cybersecurity question...")     # user input       

                  if question: # if the user types this will execute

                        with st.chat_message("user"): # icon for user
                              st.write(question)

                        st.session_state.cyber_messagers.append(
                              {
                                    'role':"user", # stores the question of the user
                                    "content":question
                              }
                        )
                        response = client.chat.completions.create(
                                    model="openai/gpt-oss-120b",
                                    messages=st.session_state.cyber_messagers   # used to allow the AI to answer
                        )
                        answer=response.choices[0].message.content
                        with st.chat_message("assistant"): # icon for assistant
                              st.write(answer) # writes down the answer 
                              
                        st.session_state.cyber_messagers.append(
                              {
                                    'role':"assistant",
                                    "content":answer
                              } #this stores the answer of the AI itself
                        )
                  if st.button("New Chat",key="cyber_new"): # this has been given a specific key to prevent mix ups of too many buttons
                        st.session_state.cyber_messagers = [
                        {
                              "role": "system",
                              "content": cyber_prompt
                        }
                        ]
                        st.rerun() # if user decides to create a new page with a fresh memory he or she needs to simply  press the new chat button which reruns eveyrhting
                        
            with it_tickets:
                  st.subheader("💻 IT Operations Assistant") # Assistant for the IT Tickets

                  it_ticket_prompt="""You are an IT operations lead. Prioritise support tickets by impact and urgency,
                  suggest troubleshooting steps and provide infrastructure best practices.
                  You must ONLY answer questions related to IT support, help desk operations, infrastructure, hardware, software, 
                  networking, operating systems, user account management, printers, servers, cloud services, and IT ticket management.
                  If the users questions does not correlate with IT support or help desk operations etc.. politely respond with : 
                  I am sorry I was designed to only answer questions related to IT support or queries regarding infrastructure. Please ask a question 
                  related to IT support or infrastructure, and I'll be happy to assist you."""

                  if 'it_messagers' not in st.session_state:
                        st.session_state.it_messagers=[
                              {
                                    'role':'system',
                                    "content" : it_ticket_prompt
                              } # Stores the it ticket prompt
                        ]
                  for message in st.session_state.it_messagers:
                        if message["role"] != 'system':
                              with st.chat_message(message['role']):  # For the icon of the AI
                                    st.write(message['content']) # writes the message
            
                  question= st.chat_input("Ask an IT support question...")       

                  if question:

                        with st.chat_message("user"):# icon for user
                              st.write(question)

                        st.session_state.it_messagers.append(
                              {
                                    'role':"user",
                                    "content":question # stores the question of the user
                              }
                        )
                        response = client.chat.completions.create(
                                    model="openai/gpt-oss-120b",
                                    messages=st.session_state.it_messagers
                        ) # for the response of the ai
                        answer=response.choices[0].message.content
                        with st.chat_message("assistant"):
                              st.write(answer) # writes the answer
                              
                        st.session_state.it_messagers.append(
                              {
                                    'role':"assistant",
                                    "content":answer
                              } # stores the answer
                        )
                  if st.button("New Chat",key="IT_new"): # new key to prevent mix ups between buttons
                        st.session_state.it_messagers = [
                        {
                              "role": "system",
                              "content": it_ticket_prompt
                        }
                        ]
                        st.rerun() # same concept as the previous new page button 

            with Metadata: # AI assistant for the metadata
                  st.subheader("📊 Data Science Assistant") 
                  question= st.chat_input("Ask a data science question...")
                  data_science_prompt="""You are a data science expert. Help with dataset analysis, choosing visualisation types,  
                  statistical methods and machine learning. Suggest concrete next steps. 
                  You must ONLY answer questions related to data analysis, datasets, data visualisation, statistics, machine learning, 
                  data preprocessing, feature engineering, model evaluation, and data-driven decision making. 
                  If the user's question does not concern data science or data analysis, politely respond with:
                  I am designed to assist only with data science and dataset analysis. Please ask a question related to data analysis, 
                  visualisation, statistics, or machine learning and I'll gladly assist you!"""

                  if 'meta' not in st.session_state: # use session state to store messages/prompts
                        st.session_state.meta=[
                              {
                                    'role':'system',
                                    "content" : data_science_prompt
                              }
                        ] # stores the prompt
                  for message in st.session_state.meta:
                        if message["role"] != 'system':
                              with st.chat_message(message['role']): # icon
                                    st.write(message['content'])   # writes the message 

                  if question:

                        with st.chat_message("user"):# icon user
                              st.write(question)  # writes user message/ question

                        st.session_state.meta.append(
                              {
                                    'role':"user",
                                    "content":question
                              }
                        )# stores the question of the user
                        response = client.chat.completions.create(
                                    model="openai/gpt-oss-120b",
                                    messages=st.session_state.meta
                        )
                        answer=response.choices[0].message.content
                        with st.chat_message("assistant"): # icon AI
                              st.write(answer)
                              
                        st.session_state.meta.append(
                              {
                                    'role':"assistant",
                                    "content":answer
                              } # stores the answer of the assistant
                        )
                  if st.button("New Chat",key="Meta_new"): # new key to prevent mix ups between buttons
                        st.session_state.meta = [
                        {
                              "role": "system",
                              "content": data_science_prompt
                        }
                        ]                       
                        st.rerun()  # same concept as previous new chat button

      elif page == "User Profile": # user page
            st.title("User Profile") 

            pfp_path = profile_picture(conn) # finds the path of the pfp for the specific user

            if pfp_path:
                  circular_image(pfp_path) # displays the picture in that was found in the path in a circular traditional format
            else:
                  circular_image("Profile_Pictures/default pfp.jpg") # If no pictures have been found in the path its going to be a default picture
                  
            col1, col2= st.columns(2)
            with col1: # used a column to reduce the length of the browsing data for aesthetic purposes
                  uploaded_file = st.file_uploader(
                  "Choose a profile picture",
                  type=["png", "jpg", "jpeg"]
                  ) # 3 types of format accepted

            if uploaded_file is not None:
                  
                  if st.button("Save Profile Picture"): # once user uploads his picture he can press the button to save the pfp

                        os.makedirs("Profile_Pictures", exist_ok=True) # makes the directory for the pfp that the user uploaded if it exists already it won't create it
                        filename = f"Profile_Pictures/{st.session_state.username}.png"  # the file name
                        with open(filename, "wb") as f:
                              f.write(uploaded_file.getbuffer())
                        st.success("Profile picture uploaded!")   # message after successful upload
                        update_pfp(conn,filename) # updates the pfp on the sidebar and on the user profile page
                        st.rerun()

            st.subheader("User Info")
            st.divider()
            st.write(f"Username: {st.session_state.username}")   # displays username of the user
            with st.expander("Change Username"): 

                  New_name=st.text_input("Enter New Username") # option to allow user to change their username
                  if st.button("Save New Username"): 
                        if New_name.strip() == "":
                              st.error("Username cannot be empty")
                        else:
                              update_user(conn,st.session_state.username,New_name) # this function will change the username of the user with the newly typed on in the database
                              st.session_state.username = New_name
                              st.success("Username successfully updated!")
                              st.rerun()

            email_ = get_mail(conn,st.session_state.username)
            st.write(f"Email Address: {email_}") # displayes the email of the user

            with st.expander("Change Password"):
                  new_password = st.text_input(
                        "Enter New Password",
                        type="password"
                  ) # change password feature

                  if st.button("Confirm Password"):

                        if new_password.strip() == "": # if password is empty error msg.
                              st.error("Please enter a password.")

                        else:
                              change_pw(conn, new_password) # updates the database 
                              st.success("Password changed successfully!")
                              st.rerun() # no 2FA is required since the user has signed in using 2FA 
            if st.button("Delete Account", type="primary"):  # the type is just used to give the delete button the red colour 
                  delete_user(conn,st.session_state.username) # If the user wants to delete their account, they have the freedom to do so
                  st.session_state.logged_in = False # user sent back to the login page
                  st.rerun()

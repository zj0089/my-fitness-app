import hashlib
import random
import smtplib
import sqlite3
import string
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import bcrypt
import matplotlib.pyplot as plt
import pandas as pd
import requests
import streamlit as st
from decouple import config
from streamlit_lottie import st_lottie

# Initialize session state
if "user" not in st.session_state:
    st.session_state.user = None

st.set_page_config(
    page_title="My Fitness App",
    page_icon="💪",
)

# Load environment variables
GMAIL_USER = "myfitness.app2024 @ gmail.com"
GMAIL_PASSWORD = "tlnslelhrjsdcvsl"

# Database setup
conn = sqlite3.connect("my_fitness_app.db")
c = conn.cursor()

# Create users table
c.execute(
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT,
        last_name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        gender TEXT,
        date_of_birth DATE,
        fitness_level TEXT,
        reset_token TEXT
    )
"""
)

# Create workouts table
c.execute(
    """
    CREATE TABLE IF NOT EXISTS workouts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        workout_type TEXT,
        duration INTEGER,
        difficulty TEXT,
        weight INTEGER,
        height INTEGER,
        workout_days INTEGER,
        date_added DATE,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
"""
)

# Create contacts table
c.execute(
    """
    CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        email TEXT,
        subject TEXT,
        message TEXT,
        date_sent DATE
    )
"""
)


# Function to hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Function to generate a random reset token
def generate_reset_token():
    return "".join(random.choices(string.ascii_letters + string.digits, k=20))


# User registration
def register_user():
    st.title("Register")
    first_name = st.text_input("First Name")
    last_name = st.text_input("Last Name")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    # Set the range for date of birth
    min_dob = datetime(1900, 1, 1)
    max_dob = datetime.now()

    dob = st.date_input("Date of Birth", min_value=min_dob, max_value=max_dob)
    gender = st.selectbox("Gender", ["Male", "Female", "Other"])

    fitness_level = st.selectbox(
        "Fitness Level", ["Beginner", "Intermediate", "Advanced"]
    )

    if st.button("Register"):
        # Check if the email already exists
        existing_user = c.execute(
            "SELECT * FROM users WHERE email=?", (email,)
        ).fetchone()
        if existing_user:
            st.error(
                "This email is already registered. Please choose a different email."
            )
            return

        # Validate and store the user in the database
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        reset_token = generate_reset_token()
        c.execute(
            """
            INSERT INTO users (first_name, last_name, email, password, gender, date_of_birth, fitness_level, reset_token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                first_name,
                last_name,
                email,
                hashed_password.decode("utf-8"),  # Decode to store as a plain string
                gender,
                dob,
                fitness_level,
                reset_token,
            ),
        )
        conn.commit()

        # Send confirmation email
        send_confirmation_email(email)

        st.success("Registration successful. You can now log in.")


# Function to send confirmation email
def send_confirmation_email(email):
    subject = "Welcome to My Fitness App - Confirmation Email"
    body = "Thank you for registering with My Fitness App. Your account has been successfully created."

    send_email(email, subject, body)


# Function to send email
def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg.attach(MIMEText(body, "plain"))
    msg["From"] = GMAIL_USER
    msg["To"] = to_email
    msg["Subject"] = subject

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_USER, GMAIL_PASSWORD)
            text = msg.as_string()
            server.sendmail(GMAIL_USER, to_email, text)

        print("Email sent successfully.")
        st.success("Email sent successfully.")
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP Authentication Error: {e}")
        st.error("SMTP Authentication Error: Check your username and password.")
    except Exception as e:
        print(f"Error sending email: {e}")
        st.error("An error occurred while sending the email.")


# User login
def login_user(email, password):
    result = c.execute(
        """
        SELECT * FROM users WHERE email=?
    """,
        (email,),
    ).fetchone()

    if result:
        hashed_password = result[4]  # Fetch the hashed password from the database
        if bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8")):
            st.session_state.user = result
            msg = st.empty()
            msg.success("Login successful.")
            time.sleep(1)
            msg.empty()
            return True
        else:
            st.error("Invalid email or password.")
            return None
    else:
        st.error("Invalid email or password.")
        return None


# Forgot Password
def forgot_password():
    email = st.text_input("Email", key="forgot_password_email")
    if st.button("Send Reset Email"):
        existing_user = c.execute(
            "SELECT * FROM users WHERE email=?", (email,)
        ).fetchone()
        if existing_user:
            reset_token = generate_reset_token()
            c.execute(
                """
                UPDATE users SET reset_token=? WHERE email=?
                """,
                (reset_token, email),
            )
            conn.commit()
            st.success("Reset email sent. Check your inbox for further instructions.")
        else:
            st.warning("Invalid email. Please try again.")


# Logout function
def logout_user():
    st.session_state.pop("user", None)
    st.success("Logged out successfully.")


# Function to delete user
def delete_user():
    if st.session_state.user:
        print(st.session_state)
        user_id = st.session_state.user[0]
        try:
            # Delete user's workouts
            c.execute("DELETE FROM workouts WHERE user_id=?", (user_id,))

            # Delete user's contacts
            c.execute("DELETE FROM contacts WHERE user_id=?", (user_id,))

            # Delete the user
            c.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.commit()

            print("User deleted successfully.")
            st.success("User deleted successfully.")

            # Clear session state
            st.session_state.user = None
            print(st.session_state)

            # Display a message and redirect to the login page
            st.warning("Your account has been deleted.")

            # Add a delay to allow the message to be displayed
            time.sleep(2)

            # Redirect to login page
            st.session_state.page = "Login"
            # st.rerun()

        except Exception as e:
            print(f"Error deleting user: {e}")
            st.error("An error occurred while deleting the user.")
    else:
        st.warning("Please log in to delete your account.")


# User profile
def view_profile(user):
    st.title("User Profile")

    if user:
        st.write(f"Name: {user[1]} {user[2]}")
        st.write(f"Email: {user[3]}")
        st.write(f"Gender: {user[5]}")
        st.write(f"Date of Birth: {user[6]}")
        st.write(f"Fitness Level: {user[7]}")

        delete_btn = st.button("Delete Account")

        if delete_btn:
            print("DELETE BUTTON CLICKED")
            # Display a confirmation dialog
            st.warning("Are you sure you want to delete your account?")
            st.button("Yes, delete my account", on_click=delete_user)
    else:
        st.warning("Please log in to view your profile.")


# User dashboard
def add_workout(user):
    if user:
        st.title("User Dashboard")
        workout_type = st.selectbox(
            "Type of Workout", ["Cardio", "Strength Training", "Flexibility"]
        )
        duration = st.number_input("Duration (minutes)", min_value=1)
        difficulty = st.selectbox("Difficulty", ["Easy", "Medium", "Hard"])
        weight = st.number_input("Weight (kg)", min_value=0)
        height = st.number_input("Height (cm)", min_value=0)
        workout_days = st.number_input("Number of Days Workout", min_value=1)

        if st.button("Add Workout"):
            date_added = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute(
                """
                INSERT INTO workouts (user_id, workout_type, duration, difficulty, weight, height, workout_days, date_added)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    user[0],
                    workout_type,
                    duration,
                    difficulty,
                    weight,
                    height,
                    workout_days,
                    date_added,
                ),
            )
            conn.commit()
            st.success("Workout added successfully.")


# Function to fetch workout data for a user
def get_user_workouts(user_id):
    workouts = c.execute(
        """
        SELECT date_added, duration, weight
        FROM workouts
        WHERE user_id=?
        ORDER BY date_added
    """,
        (user_id,),
    ).fetchall()

    return workouts


# Display data visualization
def display_visualization(user):
    st.title("Workout Visualization")

    if user and isinstance(user, tuple) and len(user) > 0:
        user_id = user[0]
        workouts = get_user_workouts(user_id)

        if workouts:
            # Create a DataFrame from the workout data
            df = pd.DataFrame(workouts, columns=["Date", "Duration", "Weight"])

            # Convert 'Date' column to datetime format
            df["Date"] = pd.to_datetime(df["Date"])

            # Line chart for workout duration over days
            fig, ax1 = plt.subplots(figsize=(10, 6))
            ax1.plot(
                df["Date"],
                df["Duration"],
                marker="o",
                color="b",
                label="Duration (minutes)",
            )
            ax1.set_xlabel("Date")
            ax1.set_ylabel("Duration (minutes)", color="b")
            ax1.tick_params("y", colors="b")
            ax1.set_title("Workout Duration Over Days")

            # Bar chart for change in weight
            ax2 = ax1.twinx()
            ax2.bar(df["Date"], df["Weight"], alpha=0.5, color="r", label="Weight (kg)")
            ax2.set_ylabel("Weight (kg)", color="r")
            ax2.tick_params("y", colors="r")

            # Display the Matplotlib plot using Streamlit
            st.pyplot(fig)
        else:
            st.warning("No workout data available.")
    else:
        st.warning("Please log in to view the visualization.")


# Workouts page
def workouts_main():
    st.title("Select A Workout")

    # List of workout options with corresponding YouTube links
    workouts = {
        "20 minute HIIT Cardio": "https://youtu.be/FeR-4_Opt-g?si=0-nHadML4Znr_Bmx",
        "28 minute Full Body Stretch": "https://youtu.be/CY6QP4ofwx4?si=e164Oouj2_i7m_Ej",
        "30 minute Full Body Strength Workout": "https://youtu.be/tj0o8aH9vJw?si=KaQmNDyThxfwN6ug",
        "30 minute Full Body Resistance Training with Dumbbells": "https://youtu.be/t3kL5gswXAc?si=mPKMdkyZcyldShCS",
        "10 minute Daily Aa Workout": "https://youtu.be/P3tx4koLhW4?si=QlsH-a0SyBz2TtLM",
        "10 minute Morning Workout (No Equipment)": "https://youtu.be/3sEeVJEXTfY?si=8q8oqHIKGgGPSjWd",
    }

    # Dropdown to select a workout
    selected_workout = st.selectbox("Select a Workout", list(workouts.keys()))

    # Display the selected workout video
    st.write(f"Selected Workout: {selected_workout}")
    st.write(f"Video Link: {workouts[selected_workout]}")
    st.video(workouts[selected_workout])


# Contacts page
def contact_us():
    st.title("Contact Us")
    name = st.text_input("Your Name")
    email = st.text_input("Your Email")
    subject = st.text_input("Subject")
    message = st.text_area("Message", height=200)

    if st.button("Submit Inquiry"):
        date_sent = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user_id = (
            st.session_state.user[0]
            if ("user" in st.session_state and st.session_state.user)
            else None
        )

        c.execute(
            """
            INSERT INTO contacts (user_id, name, email, subject, message, date_sent)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (user_id, name, email, subject, message, date_sent),
        )
        conn.commit()
        st.success("Inquiry submitted successfully. We will get back to you soon.")


# Function to check if user exists in the database
def check_user_exists(user_id):
    result = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return result is not None


def load_lottieurl(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()


# Load animation
lottie_coding = load_lottieurl(
    "https://lottie.host/59cf70ce-2625-417b-bf90-326b3d3ef9aa/ucKwhMc9p2.json"
)


# Main app
def main():
    st.sidebar.title("My Fitness App")
    page = st.sidebar.radio(
        "Select Page",
        [
            "Home",
            "Workouts",
            "Register",
            "Login",
            "Profile",
            "Dashboard",
            "Contact Us",
        ],
        index=st.session_state.page_index,
    )

    if page == "Home":
        st.title("Welcome to My Fitness App")
        st.write(
            "My Fitness is designed to help users achieve their fitness goals by providing a comprehensive set of features to track workouts, set goals, monitor progress, and access a library of exercise routines. With a user-friendly interface and personalized recommendations, our app aims to make fitness accessible and enjoyable for users of all levels. Whether you're a beginner looking to start a fitness journey or a seasoned athlete aiming to optimize performance, our app has something for everyone."
        )
        if st.button("Go to Login"):
            st.session_state.page_index = 3
            st.rerun()
    elif page == "Register":
        register_user()
    elif page == "Login":
        placeholder = st.empty()
        with placeholder.container():
            if st.session_state.user is None:
                st.title("User Login")
                email = st.text_input("Email")
                password = st.text_input("Password", type="password")
                login_btn = st.button(
                    "Login", type="primary", on_click=login_user, args=(email, password)
                )
                st.title("Forgot Password")
                forgot_password()

            elif "user" in st.session_state:
                placeholder.empty()
                placeholder.info("You are logged in.")

    elif page == "Profile":
        if st.session_state.user and check_user_exists(st.session_state.user[0]):
            view_profile(st.session_state.user)  # Pass the user to view_profile
        else:
            st.warning("Please log in to view your profile.")
    elif page == "Dashboard":
        if st.session_state.user and check_user_exists(st.session_state.user[0]):
            add_workout(st.session_state.user)
            display_visualization(st.session_state.user)
        else:
            st.warning("Please log in to access the dashboard.")
    elif page == "Contact Us":
        contact_us()
    elif page == "Workouts":
        workouts_main()

    # Check if 'user' key exists before accessing it
    if st.session_state.user:
        st.sidebar.button("Logout", on_click=logout_user)
    else:
        st.sidebar.warning("Please log in to access the app.")


if __name__ == "__main__":
    main()

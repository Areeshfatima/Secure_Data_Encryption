import streamlit as st
import hashlib                           # make password hash
import json                              # to save ad load data
import os                                # operating system
import time                              # for delay
from cryptography.fernet import Fernet   # for encrypting and decrypting data
from base64 import urlsafe_b64encode     # for see our encryption key
from hashlib import pbkdf2_hmac          # for secure password


# Data Information of user

DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOGOUT_DURATION = 60


# For Login Details

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "attempts_failed" not in st.session_state:
    st.session_state.attempts_failed = 0

if "logout_time" not in st.session_state:
    st.session_state.logout_time = 0


# If Data is Load

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return{}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)
        
def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)       #readable buffer key
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

# Using Cryptography.farnet

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None

stored_data = load_data()

# Navigation bar

st.markdown("## 🔐 *Secure Data Encryption System.*")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# Show login info and logout option

if st.session_state.authenticated_user:
    st.sidebar.markdown(f"*Logged in as* `{st.session_state.authenticated_user}`")
    if st.sidebar.button("🔓 Logout"):
        st.session_state.authenticated_user = None
        st.success("👋 Logged out successfully.")

# Navigation handling

if choice == "Home":
    st.subheader("Welcome! to my 🔐 Secure Data Encryption System!💾")
    st.markdown("The **Secure Data Encryption System** is designed to protect sensitive information using advanced encryption techniques. It ensures data confidentiality, integrity, and security both at rest and in transit.")

# User Registration

elif choice == "Register":
    st.subheader("👤 Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type = "password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User Already exists.")
            else:
                stored_data[username] = {
                    "password" : hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("🎯 User Register Successfully!")
        else:
            st.error("❗ Both field are required.")
elif choice == "Login":
        st.subheader("🔐 User Login")

        if time.time() < st.session_state.logout_time:
            remaining = int(st.session_state.logout_time - time.time())
            st.error(f"🚫 Too many failed attempts. Please wait {remaining} seconds.🔁")
            st.stop()
        
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.attempts_failed = 0
                st.success(f"Welcome! {username}✨")
            else:
                st.session_state.attempts_failed += 1
                remaining = 3 - st.session_state.attempts_failed
                st.error(f"❌Invalid Credentials! Attempts left: {remaining}⏳")

                if st.session_state.attempts_failed >= 3:
                    st.session_state.logout_time = time.time() + LOGOUT_DURATION
                    st.error("Too many failed attempts. Please try again in 60 seconds.🔐⏱️")
                    st.stop()

# Data store Section

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first to continue.😊🔐")
    else:
        st.subheader("🔐💾Store Encrypted Data:")
        data = st.text_area("Input data for encryption.💻🔐")
        passkey = st.text_input("Encryption key(passphrase)", type= "password")

        if st.button("Encrypt & Store securely 🛡️📁"): 
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Successfully encrypted and saved your data.🔐📦✔️")

            else:
                st.error("All fields are required.❗📝")

# Data Retrieve Section

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first to continue.😊🔐")
    else:
        st.subheader("📥🔍Retrieve Data:")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("Oops! No Data Found.🔍🚫")
        else:
            st.write("🔑📝Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language= "text")

            encrypted_input = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type= "password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted : {result}")
                else:
                    st.error("🔑❌ Incorrect passkey or corrupted data")




import streamlit as st
from db import init_db, save_data, get_user_data_titles, get_encrypted_data_by_id
from encryption import encrypt_data, decrypt_data
from auth import init_auth_state, login, register, logout

# Initialize DB + Auth
init_db()
init_auth_state()

st.set_page_config(page_title="🔐 Secure Data Vault", layout="centered")
st.title("🔐 Secure Data Encryption System")

# If not logged in, show Login/Register
if not st.session_state.logged_in:
    st.sidebar.subheader("🔑 Authentication")
    auth_option = st.sidebar.radio("Choose:", ["Login", "Register"])

    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")

    if auth_option == "Login":
        if st.sidebar.button("Login"):
            if login(username, password):
                st.success("✅ Login successful!")
                st.rerun()
            else:
                attempts = st.session_state.failed_attempts
                st.error(f"❌ Login failed! Attempts left: {3 - attempts}")
                if attempts >= 3:
                    st.warning("🔒 Too many failed attempts. Please try again later.")

    elif auth_option == "Register":
        if st.sidebar.button("Register"):
            if register(username, password):
                st.success("✅ Registered & logged in!")
                st.rerun()
            else:
                st.error("❌ Username already exists!")

else:
    # Sidebar menu for logged-in users
    menu = st.sidebar.radio("Navigation", ["🏠 Home", "📂 Store Data", "🔍 Retrieve Data", "🚪 Logout"])

    st.sidebar.markdown(f"👤 Logged in as: `{st.session_state.username}`")

    if menu == "🏠 Home":
        st.subheader("🏠 Welcome to Your Secure Vault")
        st.write("Use the sidebar to store or retrieve encrypted data using your custom passkey.")

    elif menu == "📂 Store Data":
        st.subheader("📂 Store Data Securely")

        title = st.text_input("Data Title (e.g., Bank Password)")
        text_data = st.text_area("Enter the Data to Encrypt:")
        passkey = st.text_input("Enter Your Secret Passkey", type="password")

        if st.button("Encrypt & Save"):
            if title and text_data and passkey:
                encrypted = encrypt_data(text_data, passkey)
                save_data(st.session_state.user_id, title, encrypted)
                st.success("✅ Data encrypted and stored successfully!")
            else:
                st.error("⚠️ All fields are required.")

    elif menu == "🔍 Retrieve Data":
        st.subheader("🔍 Retrieve Your Data")

        entries = get_user_data_titles(st.session_state.user_id)
        if entries:
            entry_dict = {title: data_id for data_id, title in entries}
            selected_title = st.selectbox("Select a Stored Entry", list(entry_dict.keys()))
            passkey = st.text_input("Enter the Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                encrypted_text = get_encrypted_data_by_id(entry_dict[selected_title], st.session_state.user_id)
                decrypted = decrypt_data(encrypted_text, passkey)

                if decrypted:
                    st.success("✅ Data Decrypted Successfully")
                    st.code(decrypted)
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    st.error(f"❌ Incorrect passkey! Attempts left: {3 - st.session_state.failed_attempts}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Locked out due to too many attempts. Please log in again.")
                        logout()
                        st.rerun()
        else:
            st.info("ℹ️ No data found. Go to 'Store Data' to save your first entry.")

    elif menu == "🚪 Logout":
        logout()
        st.success("👋 Logged out successfully.")
        st.rerun()

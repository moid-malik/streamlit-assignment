import streamlit as st
from encryption import hash_password
from db import get_user, add_user

# Initialize auth state
def init_auth_state():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.session_state.username = ""
        st.session_state.failed_attempts = 0

def login(username, password):
    user = get_user(username)
    if user:
        user_id, uname, hashed = user
        if hash_password(password) == hashed:
            st.session_state.logged_in = True
            st.session_state.user_id = user_id
            st.session_state.username = uname
            st.session_state.failed_attempts = 0
            return True
        else:
            st.session_state.failed_attempts += 1
    else:
        st.session_state.failed_attempts += 1
    return False

def register(username, password):
    try:
        hashed = hash_password(password)
        user_id = add_user(username, hashed)
        st.session_state.logged_in = True
        st.session_state.user_id = user_id
        st.session_state.username = username
        return True
    except Exception:
        return False

def logout():
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.username = ""
    st.session_state.failed_attempts = 0

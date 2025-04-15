import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = "postgresql://data-encrypt%2Fdecrypt_owner:npg_6gIzkbd2EuQS@ep-floral-rice-a5bnbr8z-pooler.us-east-2.aws.neon.tech/data-encrypt%2Fdecrypt?sslmode=require"

def get_connection():
    return psycopg2.connect(DATABASE_URL, sslmode="require")

def init_db():
    with get_connection() as conn:
        with conn.cursor() as cur:
            # Create users table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                );
            """)
            
            # Create data table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS data (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    title TEXT NOT NULL,
                    encrypted_text TEXT NOT NULL
                );
            """)
            conn.commit()

def add_user(username, password_hash):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO users (username, password) VALUES (%s, %s) RETURNING id;", (username, password_hash))
            conn.commit()
            return cur.fetchone()[0]

def get_user(username):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, password FROM users WHERE username = %s;", (username,))
            return cur.fetchone()

def save_data(user_id, title, encrypted_text):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO data (user_id, title, encrypted_text) VALUES (%s, %s, %s);", (user_id, title, encrypted_text))
            conn.commit()

def get_user_data_titles(user_id):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, title FROM data WHERE user_id = %s;", (user_id,))
            return cur.fetchall()

def get_encrypted_data_by_id(data_id, user_id):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT encrypted_text FROM data WHERE id = %s AND user_id = %s;", (data_id, user_id))
            result = cur.fetchone()
            return result[0] if result else None

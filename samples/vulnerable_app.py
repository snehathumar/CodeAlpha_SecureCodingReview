import hashlib
import os
import sqlite3

DB_PASSWORD = "insecure-dev-password-123"


def get_user_record(username: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT id, username, role FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def ping_service(host: str):
    os.system("ping -c 1 " + host)


def hash_password(raw_password: str) -> str:
    return hashlib.md5(raw_password.encode()).hexdigest()


def run_user_expression():
    return eval(input())

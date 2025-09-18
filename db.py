import sqlite3

DB_NAME = "trapscan.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        input TEXT,
        domain TEXT,
        status TEXT,
        source TEXT,
        details TEXT,
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

def save_scan(input_value, domain, status, source, details):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (input, domain, status, source, details)
        VALUES (?, ?, ?, ?, ?)
    """, (input_value, domain, status, source, details))
    conn.commit()
    row_id = cursor.lastrowid
    cursor.execute("SELECT * FROM scans WHERE id=?", (row_id,))
    row = cursor.fetchone()
    conn.close()
    return row  # Return full row for PDF

def fetch_history():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY scan_date DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

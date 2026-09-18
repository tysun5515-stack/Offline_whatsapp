import sqlite3
import uuid
import sys
import os

# Create mock db
DB_PATH = 'test_app.db'
if os.path.exists(DB_PATH): os.remove(DB_PATH)

conn = sqlite3.connect(DB_PATH)
conn.execute('''CREATE TABLE whatsapp_packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT,
    upload_id TEXT,
    filename TEXT,
    packet_no INTEGER,
    timestamp REAL,
    src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
    protocol TEXT, length INTEGER, flow_id TEXT,
    whatsapp_confidence TEXT, whatsapp_media_guess TEXT,
    sub_activity TEXT, ip_ttl INTEGER, is_stun_binding INTEGER
)''')

def insert_whatsapp_packets(batch_id, upload_id, filename, packets):
    conn.execute("DELETE FROM whatsapp_packets WHERE upload_id = ?", (upload_id,))
    conn.executemany("INSERT INTO whatsapp_packets (batch_id, upload_id, filename) VALUES (?,?,?)",
                     [(batch_id, upload_id, filename) for _ in packets])
    conn.commit()

# Simulating app.py processing
uids = [uuid.uuid4().hex for _ in range(4)]
for i, uid in enumerate(uids):
    insert_whatsapp_packets(uid, uid, f"file_{i}", [{"packet_no": 1}])

# Fetch all
rows = conn.execute("SELECT upload_id, filename FROM whatsapp_packets").fetchall()
print("ROWS in DB:", rows)

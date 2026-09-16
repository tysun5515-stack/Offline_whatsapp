"""
db.py: Handles database persistence for the WhatsApp pipeline.
"""

import sqlite3
import os
from typing import List, Dict, Any

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'whatsapp.db'))

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whatsapp_packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pcap_id TEXT NOT NULL,
            packet_no INTEGER NOT NULL,
            timestamp REAL NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            length INTEGER,
            flow_id TEXT NOT NULL,
            whatsapp_confidence TEXT NOT NULL,
            whatsapp_media_guess TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS parties (
            party_id TEXT PRIMARY KEY,
            pcap_id TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT NOT NULL,
            packet_count INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            party_type TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip TEXT PRIMARY KEY,
            country TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL,
            asn TEXT,
            asn_org TEXT,
            looked_up_at REAL,
            rdns_hostname TEXT
        )
    """)
    # Migration: add rdns_hostname column if it doesn't exist yet
    # (for databases created before Task 6)
    cursor.execute("PRAGMA table_info(geo_cache)")
    existing_columns = {row[1] for row in cursor.fetchall()}
    if "rdns_hostname" not in existing_columns:
        cursor.execute("ALTER TABLE geo_cache ADD COLUMN rdns_hostname TEXT")
    conn.commit()
    conn.close()

def insert_whatsapp_packets(pcap_id: str, packets: List[Dict[str, Any]]):
    """
    Inserts packet records into the database.
    Selection rule: First 100 packets (ordered by timestamp) for flows 
    with high or medium confidence.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Packets are expected to be enriched with 'whatsapp_confidence' 
    # and 'whatsapp_media_guess' during the pipeline phase.
    
    insert_query = """
        INSERT INTO whatsapp_packets (
            pcap_id, packet_no, timestamp, src_ip, dst_ip, src_port, 
            dst_port, protocol, length, flow_id, whatsapp_confidence, whatsapp_media_guess
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    
    # Sort by timestamp
    packets.sort(key=lambda x: x['timestamp'])
    
    # Apply limit
    if len(packets) > 100:
        print(f"Warning: Capture has {len(packets)} qualifying packets. Limiting to first 100.")
        packets_to_insert = packets[:100]
    else:
        packets_to_insert = packets
        
    for p in packets_to_insert:
        cursor.execute(insert_query, (
            pcap_id, p['packet_no'], p['timestamp'], p['src_ip'], p['dst_ip'],
            p.get('src_port'), p.get('dst_port'), p.get('protocol'), 
            p.get('length'), p.get('flow_id'), p['whatsapp_confidence'], 
            p.get('whatsapp_media_guess')
        ))
        
    conn.commit()
    conn.close()
    print(f"Inserted {len(packets_to_insert)} packets into database.")

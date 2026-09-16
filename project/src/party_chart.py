"""
party_chart.py: Generates bar and pie charts for party packet distribution.
"""

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for server environments
import matplotlib.pyplot as plt
import sqlite3
import os

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'whatsapp.db'))

def generate_party_charts(pcap_id: str, output_dir: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT dst_ip, packet_count 
        FROM parties 
        WHERE pcap_id = ? 
        ORDER BY packet_count DESC
    """, (pcap_id,))
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        print(f"No party data found for {pcap_id} to generate charts.")
        return
        
    labels = [row['dst_ip'] for row in rows]
    counts = [row['packet_count'] for row in rows]
    total_packets = sum(counts)
    num_parties = len(rows)
    
    # 1. Generate Bar Chart
    plt.figure(figsize=(10, 6))
    plt.bar(labels, counts, color='skyblue', edgecolor='black')
    plt.xlabel('Party (Destination IP)')
    plt.ylabel('Packet Count')
    plt.title(f'{total_packets} WhatsApp packets across {num_parties} parties (Bar View)')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    bar_path = os.path.join(output_dir, 'party_bar.png')
    plt.savefig(bar_path)
    plt.close()
    print(f"Saved bar chart to {bar_path}")
    
    # 2. Generate Pie Chart
    plt.figure(figsize=(8, 8))
    # Limit pie slices if too many parties to maintain readability
    if len(labels) > 7:
        pie_labels = labels[:6] + ['Other']
        pie_counts = counts[:6] + [sum(counts[6:])]
    else:
        pie_labels = labels
        pie_counts = counts
        
    plt.pie(pie_counts, labels=pie_labels, autopct='%1.1f%%', startangle=140, 
            colors=plt.cm.Paired.colors)
    plt.title(f'{total_packets} WhatsApp packets across {num_parties} parties (Pie View)')
    plt.tight_layout()
    pie_path = os.path.join(output_dir, 'party_pie.png')
    plt.savefig(pie_path)
    plt.close()
    print(f"Saved pie chart to {pie_path}")

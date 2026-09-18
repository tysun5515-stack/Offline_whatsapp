import sqlite3

conn = sqlite3.connect('pcap_registry.db')
conn.row_factory = sqlite3.Row
rows = conn.execute(
    'SELECT filename, filtered_status, filtered_path, capture_start_ts FROM pcap_uploads ORDER BY capture_start_ts'
).fetchall()
conn.close()

print(f'Total records: {len(rows)}')
print()
statuses = {}
for r in rows:
    s = r['filtered_status'] or 'NULL'
    statuses[s] = statuses.get(s, 0) + 1

print('Status distribution:')
for s, cnt in sorted(statuses.items()):
    print(f'  {s}: {cnt}')

print()
print('No-match files:')
for r in rows:
    if r['filtered_status'] == 'no_whatsapp_match':
        fn = r['filename']
        fp = r['filtered_path']
        print(f'  {fn}  |  filtered_path={fp}')

print()
print('All files and status:')
for r in rows:
    fn = r['filename']
    s = r['filtered_status']
    fp = r['filtered_path']
    print(f'  {fn}  -> {s}  filtered_path={fp}')

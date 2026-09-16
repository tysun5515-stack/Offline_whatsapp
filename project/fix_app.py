import re

with open('src/webapp/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# We want to replace from # -- Default empty state -- up to # -- Traffic timeline
match = re.search(r'# -- Default empty state -+.*?(# -- Traffic timeline)', content, re.DOTALL)
if match:
    replacement = '''# -- Default empty state --------------------------------
        metrics = {
            'packet_count': 0,
            'whatsapp_count': 0,
            'unclassified_count': 0,
            'bypass_mode': False,
            'total_bytes': 0,
            'total_size_kb': '0',
            'flow_count': 0,
            'endpoint_count': 0,
            'detection_rate': 0,
        }
        traffic_timeline = []
        protocol_dist = {}
        media_dist = {}
        recent_parties = []
        top_countries = []
        top_party = None
        insights = []
        recent_events = []
        map_html = ""

        # Populate from DB if a batch is selected
        if uploads:
            upload_ids = [u['upload_id'] for u in uploads]
            packets = get_packets(None, start_ts, end_ts, upload_ids=upload_ids)
            # Persisted parties are full-case evidence. Range views are derived in memory.
            parties = group_into_entities(packets, 'evidence-scope', 'unknown')
            b_metrics = None

            if packets:
                total_bytes = sum(p.get('length') or 0 for p in packets)
                total_size_kb = total_bytes / 1024
                unique_flows = b_metrics.get('flow_count', 0) if b_metrics else len(set(p.get('flow_id') for p in packets if p.get('flow_id')))
                unique_endpoints = len(set(
                    ip for p in packets
                    for ip in [p.get('src_ip'), p.get('dst_ip')]
                    if ip
                ))

                # Detection rate: fraction positively classified as WhatsApp.
                confident = sum(
                    1 for p in packets
                    if (p.get('whatsapp_confidence') or '').lower() in ('high', 'medium', 'infrastructure')
                )
                unclassified = sum(
                    1 for p in packets
                    if (p.get('whatsapp_confidence') or '').lower() == 'unclassified'
                )
                detection_rate = round(confident / len(packets) * 100, 1) if packets else 0

                metrics = {
                    'packet_count': b_metrics.get('packet_count', 0) if b_metrics else len(packets),
                    'whatsapp_count': confident,
                    'unclassified_count': unclassified,
                    'bypass_mode': bool(b_metrics and b_metrics.get('bypass_mode')),
                    'total_bytes': total_bytes,
                    'total_size_kb': f'{total_size_kb:.1f}',
                    'flow_count': unique_flows,
                    'endpoint_count': unique_endpoints,
                    'detection_rate': detection_rate,
                }

                ''' + match.group(1)
    
    new_content = content[:match.start()] + replacement + content[match.end():]
    with open('src/webapp/app.py', 'w', encoding='utf-8') as f:
        f.write(new_content)
    print("Replaced successfully.")
else:
    print("Could not find match.")

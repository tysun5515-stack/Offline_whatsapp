import uuid
from typing import List, Dict, Any
from src.traffic_utils import extract_bursts

def build_sessions(upload_id: str, packets: List[Dict[str, Any]], parties: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sessions = []
    
    party_matchers = []
    for p in parties:
        party_matchers.append({
            'party_id': p['party_id'],
            'ip': p['remote_ip'],
            'port': p['remote_port'],
            'protocol': p['protocol'],
            'packets': []
        })
        
    for pkt in packets:
        for m in party_matchers:
            if m['protocol'] == pkt['protocol']:
                if m['ip'] in (pkt['src_ip'], pkt['dst_ip']):
                    if m['port'] is None or m['port'] in (pkt['src_port'], pkt['dst_port']):
                        m['packets'].append(pkt)
                        break
                        
    for m in party_matchers:
        if not m['packets']: continue
        
        # Split into sessions based on 60 second gap
        session_bursts = extract_bursts(m['packets'], threshold=60.0)
        
        for idx, burst in enumerate(session_bursts):
            start_ts = burst[0]['timestamp']
            end_ts = burst[-1]['timestamp']
            total_bytes = sum(b['length'] for b in burst)
            burst_count = len(extract_bursts(burst, threshold=1.0))
            
            # Bug 2 fix: check the correct labels produced by the pipeline.
            # pipeline.py stores 'photo' (not 'image'), 'voice_call', 'video_call',
            # 'audio', 'video'. Checking only 'image' meant photo/call sessions
            # always fell through and were classified as 'text'.
            media_type = "text"
            guesses = [b.get('whatsapp_media_guess') or '' for b in burst]
            voice_count = sum(1 for g in guesses if g in ('voice_call', 'audio'))
            video_count  = sum(1 for g in guesses if g in ('video_call', 'video'))
            photo_count  = sum(1 for g in guesses if g in ('photo', 'image'))

            if video_count > voice_count and video_count > photo_count: media_type = 'video_call'
            elif voice_count > photo_count and voice_count > video_count: media_type = 'voice_call'
            elif photo_count > voice_count and photo_count > video_count: media_type = 'photo'
            
            dur = max(end_ts - start_ts, 0.1)
            summary_text = f"Session (Duration: {dur:.1f}s, {total_bytes} bytes, {burst_count} bursts)"
            
            sessions.append({
                'session_id': str(uuid.uuid4()),
                'upload_id': upload_id,
                'party_id': m['party_id'],
                'start_ts': start_ts,
                'end_ts': end_ts,
                'media_type': media_type,
                'total_bytes': total_bytes,
                'burst_count': burst_count,
                'summary_text': summary_text
            })
            
    return sessions

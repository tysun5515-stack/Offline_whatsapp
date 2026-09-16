from typing import Dict, Any, List
from src.webapp.db_analysis import get_parties, get_sessions, _connect

def compare_uploads(upload_id_a: str, upload_id_b: str) -> Dict[str, Any]:
    parties_a = get_parties(upload_id_a)
    parties_b = get_parties(upload_id_b)
    
    sessions_a = get_sessions(upload_id_a)
    sessions_b = get_sessions(upload_id_b)
    
    details = []
    # Bug 15 fix: Provide clear diagnostics if data is missing
    if not parties_a or not parties_b:
        details.append("Cannot compare: One or both cases have not been analyzed yet. Please run the analysis pipeline on both cases.")
        return {
            'upload_id_a': upload_id_a,
            'upload_id_b': upload_id_b,
            'score': 0.0,
            'details': " ".join(details)
        }
        
    common_ips = set(p['remote_ip'] for p in parties_a) & set(p['remote_ip'] for p in parties_b)
    
    score = 0.0
    
    if common_ips:
        details.append(f"Found {len(common_ips)} common remote IPs.")
        
        for ip in common_ips:
            # Bug 15 fix: Distinguish P2P from infrastructure
            is_infra = False
            for p in parties_a:
                if p['remote_ip'] == ip and p.get('confidence') in ('high', 'infrastructure') and p.get('party_type') == 'client_to_server':
                    is_infra = True
                    break
                    
            if is_infra:
                score += 10.0 # Meta server
                details.append(f"Common WhatsApp Infrastructure Server IP {ip}.")
            else:
                score += 50.0 # P2P match
                details.append(f"Common Peer-to-Peer Endpoint IP {ip}.")
            
            pa = [p['party_id'] for p in parties_a if p['remote_ip'] == ip]
            pb = [p['party_id'] for p in parties_b if p['remote_ip'] == ip]
            
            sa = [s for s in sessions_a if s['party_id'] in pa]
            sb = [s for s in sessions_b if s['party_id'] in pb]
            
            overlaps = 0
            for s1 in sa:
                for s2 in sb:
                    if not (s1['end_ts'] < s2['start_ts'] or s1['start_ts'] > s2['end_ts']):
                        overlaps += 1
            if overlaps > 0:
                score += 25.0
                details.append(f"Found {overlaps} overlapping sessions for IP {ip}.")
                
    if not details:
        details.append("No correlation found.")
        
    result = {
        'upload_id_a': upload_id_a,
        'upload_id_b': upload_id_b,
        'score': min(score, 100.0),
        'details': " ".join(details)
    }
    
    # Bug 15 fix: Persist comparison results
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS correlation_results (
            upload_id_a TEXT,
            upload_id_b TEXT,
            score REAL,
            details TEXT,
            PRIMARY KEY (upload_id_a, upload_id_b)
        )
    """)
    conn.execute(
        "REPLACE INTO correlation_results (upload_id_a, upload_id_b, score, details) VALUES (?, ?, ?, ?)",
        (upload_id_a, upload_id_b, result['score'], result['details'])
    )
    conn.commit()
    conn.close()
    
    return result

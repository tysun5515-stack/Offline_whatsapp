import os
import re

file_path = 'src/webapp/app.py'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add import
if 'from src.geo_enrichment import enrich_parties' not in content:
    content = content.replace(
        'from src.geo_mapping import classify_remote_party',
        'from src.geo_mapping import classify_remote_party\nfrom src.geo_enrichment import enrich_parties'
    )

# 2. Remove _enrich_endpoint_geolocation function
geo_func_pattern = r'def _enrich_endpoint_geolocation\(party\):.*?return party\n'
content = re.sub(geo_func_pattern, '', content, flags=re.DOTALL)

# 3. Replace in dashboard
dashboard_pattern = r'for party in parties\[:10\]:\n\s+row = _enrich_endpoint_geolocation\(dict\(party\)\)\n\s+remote_scope = .*?if row\.get\(\'public_local_ip\'\):\n.*?row\[\'local_geo_country\'\] = loc_geo\.get\(\'country\'\)'
dashboard_replacement = """enriched_parties = enrich_parties([dict(p) for p in parties[:10]], get_geo, upsert_geo)
                for row in enriched_parties:
                    country = row.get('geo_country')
                    if country and country != '—':
                        country_bytes[country] += row.get('total_bytes', 0)"""
content = re.sub(dashboard_pattern, dashboard_replacement, content, flags=re.DOTALL)

# 4. Replace in interface3
interface3_pattern = r'parties_data, _map_sessions = _derive_parties_and_sessions\(packets, \'evidence-scope\', \'unknown\'\)\n\s+for p in parties_data:\n\s+for side in \(\'a\', \'b\'\):.*?remote_lon\'\] = geo\.get\(\'longitude\'\)'
interface3_replacement = """parties_data, _map_sessions = _derive_parties_and_sessions(packets, 'evidence-scope', 'unknown')
            parties_data = enrich_parties(parties_data, get_geo, upsert_geo)
            for p in parties_data:
                geo = get_geo(p['remote_ip']) if p.get('remote_ip') else None"""
content = re.sub(interface3_pattern, interface3_replacement, content, flags=re.DOTALL)

# 5. Replace in api_analyze
api_analyze_pattern = r'for p in parties:\n\s+_enrich_endpoint_geolocation\(p\)'
api_analyze_replacement = 'parties = enrich_parties(parties, get_geo, upsert_geo)'
content = re.sub(api_analyze_pattern, api_analyze_replacement, content)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Refactoring complete.")

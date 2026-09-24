"""
geo_enrichment.py: Single source of truth for location enrichment.
Unifies all the disparate geolocation property names across the frontend.
"""

from typing import List, Dict, Any
from src.geolocation import geolocate
from src.geo_mapping import classify_remote_party

def enrich_parties(parties: List[Dict[str, Any]], get_geo_fn, upsert_geo_fn) -> List[Dict[str, Any]]:
    """
    Single, canonical geo enrichment pass over a party list.
    Populates: geo_country, geo_city, asn, asn_org, role_label,
    caveat_type, caveat_label, location_reliable, latitude, longitude, etc.
    """
    for party in parties:
        # Determine the side that represents the remote endpoint.
        remote_ip = party.get('remote_ip')
        if not remote_ip:
            remote_ip = party.get('endpoint_a_ip') if party.get('endpoint_a_scope') != 'local' else party.get('endpoint_b_ip')
            
        if not remote_ip:
            continue

        # Legacy remote scope handling
        remote_scope = (party.get('endpoint_a_scope') if remote_ip == party.get('endpoint_a_ip') else party.get('endpoint_b_scope'))
        
        geo = get_geo_fn(remote_ip) if remote_scope == 'public' else None
        if remote_scope == 'public' and not geo:
            geo_new = geolocate(remote_ip)
            if geo_new:
                upsert_geo_fn(remote_ip, {
                    'country': geo_new.country,
                    'city': geo_new.city,
                    'latitude': geo_new.latitude,
                    'longitude': geo_new.longitude,
                    'asn': geo_new.asn,
                    'asn_org': geo_new.asn_org,
                    'rdns_hostname': '__RDNS_NONE__'
                })
                geo = get_geo_fn(remote_ip)
                
        if party.get('traffic_class') == 'unclassified':
            classification = {
                'caveat_type': 'unclassified',
                'role_label': 'Unclassified endpoint',
                'is_server': False,
                'location_reliable': True,
                'caveat_label': 'Retained by WA Filter Bypass; no WhatsApp-specific role assigned.',
            }
        else:
            classification = classify_remote_party(
                src_ip=remote_ip,
                asn_number=geo.get('asn') if geo else None,
                asn_org=geo.get('asn_org') if geo else None,
                party_type=party.get('party_type', 'unknown'),
                port=party.get('remote_port'),
                protocol=party.get('protocol')
            )
            
        party['caveat'] = classification.get('caveat_label')
        party['caveat_type'] = classification.get('caveat_type')
        party['role_label'] = classification.get('role_label')
        party['is_server'] = classification.get('is_server', False)
        party['location_reliable'] = classification.get('location_reliable', True)
        
        # Bug 2 fix porting: Ensure is_p2p relies on geo_mapping result
        if classification.get('role_label') == 'Direct Peer':
            party['is_p2p'] = 1
        elif classification.get('caveat_type') == 'relay_server':
            party['is_p2p'] = 0
            
        if geo:
            party['geo_country'] = geo.get('country') or '—'
            party['geo_city'] = geo.get('city') or '—'
            party['asn_org'] = geo.get('asn_org') or '—'
            party['asn'] = geo.get('asn') or '—'
            party['rdns'] = geo.get('rdns_hostname')

            # Unify lat/lon variants
            party['remote_lat'] = geo.get('latitude')
            party['remote_lon'] = geo.get('longitude')
            party['latitude'] = geo.get('latitude')
            party['longitude'] = geo.get('longitude')
            # Unify country variants
            party['country'] = geo.get('country')
        else:
            party.update({
                'geo_country': '—', 'geo_city': '—',
                'asn_org': '—', 'asn': '—',
                'remote_lat': None, 'remote_lon': None,
                'latitude': None, 'longitude': None,
                'country': None
            })
            
        public_local_ip = party.get('public_local_ip')
        if public_local_ip:
            loc_geo = get_geo_fn(public_local_ip)
            if loc_geo:
                party['local_lat'] = loc_geo.get('latitude')
                party['local_lon'] = loc_geo.get('longitude')
                party['local_geo_city'] = loc_geo.get('city')
                party['local_geo_country'] = loc_geo.get('country')
                
        # Also do the endpoint_a and endpoint_b specific enrichment for full compatibility
        for side in ('a', 'b'):
            ip = party.get(f'endpoint_{side}_ip')
            scope = party.get(f'endpoint_{side}_scope')
            side_geo = get_geo_fn(ip) if ip and scope == 'public' else None
            if ip and scope == 'public' and not side_geo:
                side_geo_new = geolocate(ip)
                if side_geo_new:
                    upsert_geo_fn(ip, {
                        'country': side_geo_new.country, 'city': side_geo_new.city,
                        'latitude': side_geo_new.latitude, 'longitude': side_geo_new.longitude,
                        'asn': side_geo_new.asn, 'asn_org': side_geo_new.asn_org,
                        'rdns_hostname': '__RDNS_NONE__'
                    })
                    side_geo = get_geo_fn(ip)
            if side_geo:
                party[f'endpoint_{side}_lat'] = side_geo.get('latitude')
                party[f'endpoint_{side}_lon'] = side_geo.get('longitude')
                party[f'endpoint_{side}_country'] = side_geo.get('country')
                party[f'endpoint_{side}_city'] = side_geo.get('city')
                party[f'endpoint_{side}_asn'] = side_geo.get('asn')
                party[f'endpoint_{side}_asn_org'] = side_geo.get('asn_org')
                ports = party.get(f'endpoint_{side}_ports') or []
                role = classify_remote_party(ip, side_geo.get('asn'), side_geo.get('asn_org'), 'unknown',
                                             ports[0] if len(ports) == 1 else None, party.get('protocol'))
                party[f'endpoint_{side}_role'] = role.get('role_label')
                party[f'endpoint_{side}_caveat'] = role.get('caveat_label') or (
                    "Approximate network endpoint or infrastructure location; not a person's location."
                )
            else:
                party[f'endpoint_{side}_role'] = {
                    'local': 'Local endpoint', 'cgnat': 'CGNAT endpoint'
                }.get(scope, 'Non-geographic endpoint')
                party[f'endpoint_{side}_caveat'] = 'No geographic coordinates are asserted for this endpoint.'

    return parties

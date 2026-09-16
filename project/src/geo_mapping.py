"""
geo_mapping.py: Annotates limitations and caveats for geospatial data mapping.
"""

import ipaddress
from typing import Optional, Dict, Any

META_ASNS = {'32934', '63293', '54115', '31334', '36351'}

CDN_KEYWORDS = ['cloudflare', 'akamai', 'fastly', 'incapsula']
VPN_KEYWORDS  = ['mullvad', 'expressvpn', 'nordvpn', 'protonvpn', 'hidemyass',
                 'cyberghost', 'purevpn', 'ipvanish']
HOSTING_KEYWORDS = ['digitalocean', 'linode', 'vultr', 'hetzner', 'ovh',
                    'choopa', 'aws', 'amazon', 'google cloud', 'azure']

def classify_remote_party(
    src_ip: str, 
    asn_number: Optional[str], 
    asn_org: Optional[str], 
    party_type: str,
    port: Optional[int] = None,
    protocol: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates known limitations for a given party connection row and returns
    a structured classification dict.
    """
    if port in {53, 853} and protocol == "UDP":
        return {
            "caveat_type": "dns",
            "role_label": "DNS Resolver",
            "is_server": True,
            "location_reliable": True,
            "caveat_label": ""
        }

    caveat_type = "none"
    role_label = "Unknown"
    is_server = False
    location_reliable = False
    caveat_label = ""
    
    org_lower = (asn_org or "").lower()
    
    # Check IP space first for local/CGNAT
    is_private = False
    is_cgnat = False
    try:
        ip_obj = ipaddress.ip_address(src_ip)
        if ip_obj.is_private:
            is_private = True
        elif ip_obj.version == 4 and ipaddress.ip_network('100.64.0.0/10').overlaps(ipaddress.ip_network(src_ip)):
            is_cgnat = True
    except ValueError:
        pass

    if asn_number in META_ASNS:
        if protocol == "UDP" and (port == 3478 or (port is not None and port > 1024)):
            caveat_type = "relay_server"
            role_label = "Call Relay (TURN)"
            is_server = True
            location_reliable = False
            caveat_label = "Location is relay server's data center, NOT the actual call peer."
        elif port == 443:
            caveat_type = "whatsapp_cdn"
            role_label = "WhatsApp Media CDN"
            is_server = True
            location_reliable = True
            caveat_label = ""
        else:
            caveat_type = "whatsapp_chat"
            role_label = "WhatsApp Chat Server"
            is_server = True
            location_reliable = True
            caveat_label = ""
    elif party_type == 'peer_to_peer' and any(kw in org_lower for kw in HOSTING_KEYWORDS + VPN_KEYWORDS + CDN_KEYWORDS):
        caveat_type = "relay_server"
        role_label = "Call Relay (TURN)"
        is_server = True
        location_reliable = False
        caveat_label = "Location is relay server's data center, NOT the actual call peer."
    elif any(kw in org_lower for kw in VPN_KEYWORDS):
        caveat_type = "vpn_exit"
        role_label = "VPN Exit Node"
        is_server = True
        location_reliable = False
        caveat_label = "Location may not be real."
    elif any(kw in org_lower for kw in CDN_KEYWORDS):
        caveat_type = "cdn_proxy"
        role_label = "CDN Edge Node"
        is_server = True
        location_reliable = False
        caveat_label = "Content delivery PoP location."
    elif any(kw in org_lower for kw in HOSTING_KEYWORDS):
        caveat_type = "hosting"
        role_label = "Hosting/Cloud Server"
        is_server = True
        location_reliable = False
        caveat_label = "Data center, not user location."
    elif is_cgnat:
        caveat_type = "cgnat"
        role_label = "CGNAT Gateway"
        location_reliable = False
        caveat_label = "Source location is the operator gateway, not necessarily the device."
    elif is_private:
        caveat_type = "private"
        role_label = "Private IP"
        location_reliable = False
        caveat_label = "Location is local network, not necessarily real geographic origin."
    else:
        role_label = "Direct Peer" if party_type == 'peer_to_peer' else "Direct Server"
        location_reliable = True

    return {
        "caveat_type": caveat_type,
        "role_label": role_label,
        "is_server": is_server,
        "location_reliable": location_reliable,
        "caveat_label": caveat_label
    }

def get_row_caveat(src_ip: str, dst_asn_org: Optional[str]) -> str:
    """
    Compatibility shim. Evaluates known limitations for a given party connection row and returns
    a formatted caveat string if applicable.
    """
    res = classify_remote_party(src_ip, None, dst_asn_org, 'client_to_server')
    return res['caveat_label']


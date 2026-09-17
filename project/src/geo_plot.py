"""
geo_plot.py: Generates an interactive SVG world map visualization of WhatsApp traffic.
Pure offline dependency: uses bundled SVG world geometry with instant client-side rendering.
Consistent between Core Analysis (Interface 3) and Main Dashboard.
"""

import math
import html
import uuid
from typing import List, Dict, Any, Optional
from src.geo_svg_data import COUNTRIES_SVG

def compute_bearing(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    dlon = math.radians(lon2 - lon1)
    lat1, lat2 = math.radians(lat1), math.radians(lat2)
    x = math.sin(dlon) * math.cos(lat2)
    y = math.cos(lat1)*math.sin(lat2) - math.sin(lat1)*math.cos(lat2)*math.cos(dlon)
    return math.degrees(math.atan2(x, y))

def lon_lat_to_xy(lon: float, lat: float, width: float = 1000.0, height: float = 500.0) -> tuple:
    """Equirectangular projection from (lon, lat) to SVG coordinates (x, y)."""
    # Clamp to valid geographical boundaries
    lon = max(-180.0, min(180.0, float(lon)))
    lat = max(-90.0, min(90.0, float(lat)))
    x = (lon + 180.0) * (width / 360.0)
    y = (90.0 - lat) * (height / 180.0)
    return round(x, 1), round(y, 1)

def generate_map_html(parties_data: List[Dict[str, Any]], height: int = 360, file_color_map: Dict[str, str] = None, div_id: str = None, per_file_source_positions: Dict[str, tuple] = None, per_file_source_ips: Dict[str, str] = None) -> str:
    """
    Generates a 100% offline, self-contained interactive SVG world map.
    Plots communicating parties, connections from the Source Device,
    and provides client-side reactivity for file filtering.
    """
    container_id = div_id if div_id else f"svg_map_{uuid.uuid4().hex[:8]}"
    width = 1000
    map_height = 500

    # Role definitions: (color, label, shape)
    marker_colors = {
        'whatsapp_chat': ('#3B82F6', 'WhatsApp Chat Server', 'rect'),
        'whatsapp_cdn': ('#8B5CF6', 'WhatsApp Media CDN', 'triangle'),
        'relay_server': ('#F97316', 'Call Relay (TURN)', 'diamond'),
        'vpn_exit': ('#EAB308', 'Possible VPN Exit', 'diamond'),
        'cdn_proxy': ('#94A3B8', 'CDN Edge Node', 'triangle'),
        'hosting': ('#A855F7', 'Hosting/Cloud Server', 'circle'),
        'cgnat': ('#F43F5E', 'CGNAT Gateway', 'circle'),
        'private': ('#F43F5E', 'Private IP', 'circle'),
        'direct_peer': ('#10B981', 'Direct Peer', 'circle'),
        'direct_server': ('#FF6B6B', 'Direct Server', 'circle'),
        'source_device': ('#0EA5E9', 'Source Device', 'source_star'),
        'unknown': ('#94A3B8', 'Unknown', 'circle'),
    }

    # Extract source device info
    source_ip = None
    source_lat = None
    source_lon = None
    source_is_private = True
    source_city = ""
    source_country = ""

    for p in parties_data:
        # Check if local geo is available
        if p.get('local_lat') is not None and p.get('local_lon') is not None:
            # Check if it's not the old placeholder (20.0, 0.0)
            if not (abs(p.get('local_lat') - 20.0) < 0.1 and abs(p.get('local_lon') - 0.0) < 0.1):
                source_lat = p.get('local_lat')
                source_lon = p.get('local_lon')
                source_is_private = False
                source_city = p.get('local_geo_city') or ''
                source_country = p.get('local_geo_country') or ''
        
        if not source_ip:
            if p.get('public_local_ip'):
                source_ip = p.get('public_local_ip')
            elif p.get('local_ips'):
                ips = [ip.strip() for ip in p.get('local_ips', '').split(',') if ip.strip()]
                if ips:
                    source_ip = ips[0]

    if not source_ip:
        source_ip = "10.0.2.15 (Local Capture)"

    # Coordinates for source device
    if source_lat is not None and source_lon is not None and not source_is_private:
        src_x, src_y = lon_lat_to_xy(source_lon, source_lat, width, map_height)
    else:
        # Designated reference anchor for private/NAT source device (Europe/Africa meridian, lat 25N)
        # Avoids Gulf of Guinea (0, 0 or 20, 0) and clearly labels as NAT/Private Device
        src_x, src_y = 520.0, 185.0

    # Group remote points to avoid stacking identical IPs
    unique_points = {}
    arcs = []

    for party in parties_data:
        rem_lat = party.get('remote_lat')
        rem_lon = party.get('remote_lon')
        if rem_lat is None or rem_lon is None:
            continue

        rem_x, rem_y = lon_lat_to_xy(rem_lon, rem_lat, width, map_height)
        party_type = party.get('party_type', 'unknown')
        caveat_type = party.get('caveat_type', 'none')
        caveat_label = party.get('caveat_label', '')
        source_file = party.get('source_file', 'Default')
        source_files = party.get('source_files', f'["{source_file}"]')
        proto = party.get('protocol', 'UDP')

        primary_type = caveat_type
        if primary_type in ('none', '', None):
            if party_type == 'peer_to_peer':
                primary_type = 'direct_peer'
            else:
                primary_type = 'direct_server'

        role_color = marker_colors.get(primary_type, marker_colors['unknown'])[0]
        role_label = party.get('role_label') or marker_colors.get(primary_type, marker_colors['unknown'])[1]
        line_color = file_color_map.get(source_file, role_color) if file_color_map else role_color

        pt_key = (rem_x, rem_y, source_file)
        if pt_key not in unique_points:
            unique_points[pt_key] = {
                'x': rem_x,
                'y': rem_y,
                'lat': rem_lat,
                'lon': rem_lon,
                'ips': set(),
                'city': party.get('geo_city') or '',
                'country': party.get('geo_country') or '',
                'asn': party.get('asn_org') or '',
                'rdns': party.get('rdns') or '',
                'role': role_label,
                'primary_type': primary_type,
                'color': role_color,
                'source_file': source_file,
                'source_files': source_files,
                'packet_count': 0,
                'bytes': party.get('total_bytes', 0),
                'caveat': caveat_label,
                'proto': proto
            }
        
        pt = unique_points[pt_key]
        pt['ips'].add(party.get('remote_ip', ''))
        pt['packet_count'] += party.get('packet_count', 0)
        if caveat_label and not pt['caveat']:
            pt['caveat'] = caveat_label

        file_src_x, file_src_y = src_x, src_y
        if per_file_source_positions and source_file in per_file_source_positions:
            file_src_x, file_src_y = per_file_source_positions[source_file]

        # Arc from Source Device to remote party
        mid_x = (file_src_x + rem_x) / 2.0
        dist = math.hypot(rem_x - file_src_x, rem_y - file_src_y)
        curve_h = min(70.0, max(18.0, dist * 0.18))
        mid_y = min(file_src_y, rem_y) - curve_h

        arcs.append({
            'd': f"M {file_src_x:.1f} {file_src_y:.1f} Q {mid_x:.1f} {mid_y:.1f} {rem_x:.1f} {rem_y:.1f}",
            'color': line_color,
            'proto': proto,
            'source_file': source_file,
            'source_files': source_files,
            'rem_ip': party.get('remote_ip', ''),
            'role': role_label,
            'pkts': party.get('packet_count', 0)
        })

    # Build country paths SVG
    countries_svg_parts = []
    for cid, path_d in COUNTRIES_SVG.items():
        countries_svg_parts.append(
            f'<path class="country-land" data-cid="{cid}" d="{path_d}" '
            f'fill="#E5E9F0" stroke="#CBD5E1" stroke-width="0.5" stroke-linejoin="round"/>'
        )
    countries_markup = "".join(countries_svg_parts)

    # Build Arcs SVG
    arcs_markup_parts = []
    for arc in arcs:
        dash_style = 'stroke-dasharray="4,3"' if arc['proto'] == 'TCP' else ''
        file_safe = html.escape(str(arc['source_file'])).replace(" ", "_").replace(".", "_")
        arcs_markup_parts.append(
            f'<path class="map-flow-arc map-file-{file_safe}" data-files="{html.escape(str(arc["source_files"]))}" '
            f'd="{arc["d"]}" fill="none" stroke="{arc["color"]}" stroke-width="1.3" opacity="0.45" {dash_style} '
            f'style="transition:opacity 0.2s ease-in-out; pointer-events:none;"/>'
        )
    arcs_markup = "".join(arcs_markup_parts)

    # Build Nodes SVG
    nodes_markup_parts = []
    for pt in unique_points.values():
        ips_str = ", ".join(filter(None, pt['ips']))
        size = min(14.0, max(5.0, 3.5 + math.sqrt(pt['packet_count'] / 4.0)))
        x, y = pt['x'], pt['y']
        c = pt['color']
        p_type = pt['primary_type']
        file_safe = html.escape(str(pt['source_file'])).replace(" ", "_").replace(".", "_")
        
        # Tooltip data
        tip_data = (
            f'data-ip="{html.escape(ips_str)}" '
            f'data-role="{html.escape(pt["role"])}" '
            f'data-country="{html.escape(pt["country"])}" '
            f'data-city="{html.escape(pt["city"])}" '
            f'data-asn="{html.escape(pt["asn"])}" '
            f'data-pkts="{pt["packet_count"]}" '
            f'data-proto="{pt["proto"]}" '
            f'data-files="{html.escape(str(pt["source_files"]))}" '
            f'data-caveat="{html.escape(pt["caveat"])}"'
        )

        shape_svg = ""
        if p_type == 'whatsapp_chat':
            # Square for chat servers
            shape_svg = f'<rect x="{x - size:.1f}" y="{y - size:.1f}" width="{size*2:.1f}" height="{size*2:.1f}" rx="2" fill="{c}" stroke="#ffffff" stroke-width="1.2"/>'
        elif p_type in ('whatsapp_cdn', 'cdn_proxy'):
            # Triangle for CDNs
            p1 = f"{x:.1f},{y - size*1.2:.1f}"
            p2 = f"{x + size:.1f},{y + size*0.8:.1f}"
            p3 = f"{x - size:.1f},{y + size*0.8:.1f}"
            shape_svg = f'<polygon points="{p1} {p2} {p3}" fill="{c}" stroke="#ffffff" stroke-width="1.2"/>'
        elif p_type in ('relay_server', 'vpn_exit'):
            # Diamond for Relay / VPN
            p1 = f"{x:.1f},{y - size*1.2:.1f}"
            p2 = f"{x + size*1.1:.1f},{y:.1f}"
            p3 = f"{x:.1f},{y + size*1.2:.1f}"
            p4 = f"{x - size*1.1:.1f},{y:.1f}"
            shape_svg = f'<polygon points="{p1} {p2} {p3} {p4}" fill="{c}" stroke="#ffffff" stroke-width="1.2"/>'
        else:
            # Circle for peer/server/unknown
            shape_svg = (
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{size + 2:.1f}" fill="{c}" opacity="0.25"/>'
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{size:.1f}" fill="{c}" stroke="#ffffff" stroke-width="1.2"/>'
            )

        nodes_markup_parts.append(
            f'<g class="map-node-item map-file-{file_safe} cursor-pointer" data-files="{html.escape(str(pt["source_files"]))}" '
            f'{tip_data} style="transition:opacity 0.2s ease-in-out;">'
            f'{shape_svg}'
            f'</g>'
        )

    # Add the Source Device nodes per file (geo-positioned or NAT anchor)
    source_node_parts = []

    if per_file_source_positions and file_color_map:
        # Build per-file meta from parties: file -> (ip, country, city)
        _file_src_meta = {}  # fname -> (ip, country, city, is_private)
        _DEFAULT_ANCHOR = (520.0, 185.0)

        for fname, (sx, sy) in per_file_source_positions.items():
            fcolor = file_color_map.get(fname, '#0EA5E9')
            file_safe = html.escape(str(fname)).replace(" ", "_").replace(".", "_")

            # Determine if this file is at the private/NAT anchor position
            _dx = abs(sx - _DEFAULT_ANCHOR[0])
            _dy = abs(sy - _DEFAULT_ANCHOR[1])
            _at_default = (_dx < 20 and _dy < 20)

            if _at_default:
                _tip_ip = (per_file_source_ips or {}).get(fname, source_ip) or source_ip
                _tip_country = "Private / NAT Network"
                _tip_city = "Geographic origin unknown"
                _tip_caveat = "Source captured on private/NAT network \u2014 geographic origin not determinable from packet headers."
            else:
                _tip_ip = (per_file_source_ips or {}).get(fname, source_ip) or source_ip
                _tip_country = source_country
                _tip_city = source_city
                _tip_caveat = ""

            source_node_parts.append(
                f'<g class="map-source-device map-file-{file_safe} cursor-pointer" '
                f'data-ip="{html.escape(_tip_ip)}" '
                f'data-role="Source Device" '
                f'data-country="{html.escape(_tip_country)}" '
                f'data-city="{html.escape(_tip_city)}" '
                f'data-asn="Local Host / Capture Point" '
                f'data-pkts="Source" '
                f'data-proto="Local" '
                f'data-files="{html.escape(str([fname]))}" '
                f'data-caveat="{html.escape(_tip_caveat)}">'
                f'<circle cx="{sx:.1f}" cy="{sy:.1f}" r="9" fill="{fcolor}" opacity="0.2"/>'
                f'<circle cx="{sx:.1f}" cy="{sy:.1f}" r="5.5" fill="{fcolor}" stroke="#ffffff" stroke-width="1.5"/>'
                f'<circle cx="{sx:.1f}" cy="{sy:.1f}" r="2" fill="#ffffff"/>'
                f'</g>'
            )

        # Draw group labels once per unique location cluster
        _seen_labels = set()
        for fname, (sx, sy) in per_file_source_positions.items():
            _rk = (round(sx / 20) * 20, round(sy / 20) * 20)  # cluster key
            if _rk in _seen_labels:
                continue
            _seen_labels.add(_rk)
            _dx = abs(sx - _DEFAULT_ANCHOR[0])
            _dy = abs(sy - _DEFAULT_ANCHOR[1])
            _at_default = (_dx < 25 and _dy < 25)
            _label = "Private / NAT Devices" if _at_default else "Source Device"
            source_node_parts.append(
                f'<text x="{sx:.1f}" y="{sy - 13:.1f}" text-anchor="middle" font-size="9" font-weight="700" fill="#0369A1" '
                f'filter="drop-shadow(0px 1px 2px rgba(255,255,255,0.95))">{_label}</text>'
            )
    else:
        src_caveat_text = (
            "Source captured on private/NAT network \u2014 geographic origin not determinable from packet headers."
            if source_is_private else ""
        )
        source_node_parts.append(
            f'<g class="map-source-device cursor-pointer" '
            f'data-ip="{html.escape(source_ip)}" '
            f'data-role="Source Device" '
            f'data-country="{html.escape(source_country)}" '
            f'data-city="{html.escape(source_city)}" '
            f'data-asn="Local Host / Capture Point" '
            f'data-pkts="Source" '
            f'data-proto="Local" '
            f'data-files="[]" '
            f'data-caveat="{html.escape(src_caveat_text)}">'
            f'<circle cx="{src_x:.1f}" cy="{src_y:.1f}" r="16" fill="#0EA5E9" opacity="0.15"/>'
            f'<circle cx="{src_x:.1f}" cy="{src_y:.1f}" r="11" fill="none" stroke="#0EA5E9" stroke-width="1.5" stroke-dasharray="3,2" opacity="0.75"/>'
            f'<circle cx="{src_x:.1f}" cy="{src_y:.1f}" r="6" fill="#0EA5E9" stroke="#ffffff" stroke-width="1.5"/>'
            f'<circle cx="{src_x:.1f}" cy="{src_y:.1f}" r="2" fill="#ffffff"/>'
            f'<text x="{src_x:.1f}" y="{src_y - 14:.1f}" text-anchor="middle" font-size="10" font-weight="700" fill="#0369A1" '
            f'filter="drop-shadow(0px 1px 2px rgba(255,255,255,0.9))">Source Device</text>'
            f'</g>'
        )
        
    source_node_markup = "".join(source_node_parts)
    nodes_markup = "".join(nodes_markup_parts) + source_node_markup

    # Latitude/Longitude Reference Lines (Equator, Tropics, Prime Meridian)
    graticules = (
        '<g class="graticules" opacity="0.35" stroke="#94A3B8" stroke-dasharray="2,3" stroke-width="0.6">'
        # Equator
        '<line x1="0" y1="250" x2="1000" y2="250"/>'
        # Tropic of Cancer (23.5 N)
        '<line x1="0" y1="184.7" x2="1000" y2="184.7"/>'
        # Tropic of Capricorn (23.5 S)
        '<line x1="0" y1="315.3" x2="1000" y2="315.3"/>'
        # Prime Meridian (0)
        '<line x1="500" y1="0" x2="500" y2="500"/>'
        '</g>'
    )

    return f"""
<div id="{container_id}" class="svg-world-map-wrap flex flex-col w-full h-full bg-[#f8fafc] rounded-lg overflow-hidden border border-gray-200 relative select-none" style="min-height:{height}px;">
  <!-- SVG Canvas Area -->
  <div class="relative flex-1 w-full overflow-hidden" style="min-height:{height - 40}px; background:#F0F4F8;">
    <svg viewBox="0 0 1000 500" class="w-full h-full" preserveAspectRatio="xMidYMid meet" style="display:block;">
      <defs>
        <radialGradient id="{container_id}-water-grad" cx="50%" cy="50%" r="60%">
          <stop offset="0%" stop-color="#F1F5F9" />
          <stop offset="100%" stop-color="#E2E8F0" />
        </radialGradient>
        <filter id="{container_id}-shadow" x="-20%" y="-20%" width="140%" height="140%">
          <feDropShadow dx="0" dy="1" stdDeviation="1" flood-opacity="0.15"/>
        </filter>
      </defs>
      <!-- Ocean background -->
      <rect width="1000" height="500" fill="url(#{container_id}-water-grad)"/>
      <!-- Graticule guide lines -->
      {graticules}
      <!-- Country Landmasses -->
      <g class="countries-layer" style="cursor:default;">
        {countries_markup}
      </g>
      <!-- Traffic Arcs -->
      <g class="arcs-layer">
        {arcs_markup}
      </g>
      <!-- Endpoints & Source Device Nodes -->
      <g class="nodes-layer">
        {nodes_markup}
      </g>
    </svg>

    <!-- Floating Interactive Tooltip -->
    <div id="{container_id}-tooltip" class="absolute pointer-events-none hidden z-30 bg-gray-900/95 text-white p-3 rounded-lg shadow-xl text-xs max-w-xs border border-gray-700 backdrop-blur-sm transition-opacity duration-150">
      <div class="font-bold text-sm text-sky-400 mb-0.5" id="{container_id}-tip-title">Source Device</div>
      <div class="font-mono text-gray-300 text-[11px] mb-1" id="{container_id}-tip-ip">10.0.2.15</div>
      <div class="space-y-0.5 text-gray-300 text-[11px]">
        <div id="{container_id}-tip-role-row"><span class="text-gray-400">Role:</span> <span class="font-medium" id="{container_id}-tip-role"></span></div>
        <div id="{container_id}-tip-loc-row"><span class="text-gray-400">Location:</span> <span id="{container_id}-tip-loc"></span></div>
        <div id="{container_id}-tip-asn-row"><span class="text-gray-400">ASN:</span> <span id="{container_id}-tip-asn"></span></div>
        <div id="{container_id}-tip-traffic-row"><span class="text-gray-400">Traffic:</span> <span id="{container_id}-tip-traffic"></span></div>
      </div>
      <div id="{container_id}-tip-caveat" class="hidden mt-2 pt-1.5 border-t border-amber-500/40 text-[10px] text-amber-300 font-medium leading-tight"></div>
    </div>
  </div>

  <!-- Unified Bottom Map Legend -->
  <div class="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 px-3.5 py-2 bg-white border-t border-gray-200 text-[11px] text-gray-600 shrink-0">
    <div class="flex flex-wrap items-center gap-3.5">
      <span class="font-semibold text-gray-700 text-xs">Legend:</span>
      <span class="inline-flex items-center gap-1.5" title="Local node under investigation">
        <span class="w-2.5 h-2.5 rounded-full bg-sky-500 ring-2 ring-sky-200"></span>
        <span class="font-medium text-gray-800">Source Device</span>
      </span>
      <span class="inline-flex items-center gap-1.5" title="WhatsApp signaling and messaging servers">
        <span class="w-2.5 h-2.5 rounded-sm bg-blue-500"></span> WhatsApp Chat
      </span>
      <span class="inline-flex items-center gap-1.5" title="High volume media CDN servers">
        <span class="w-2.5 h-2.5 rounded-sm bg-purple-500"></span> Media CDN
      </span>
      <span class="inline-flex items-center gap-1.5" title="Encrypted TURN relay servers">
        <span class="w-2.5 h-2.5 rotate-45 bg-orange-500"></span> Relay (TURN)
      </span>
      <span class="inline-flex items-center gap-1.5" title="Direct VoIP call peers">
        <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Direct Peer
      </span>
      <span class="inline-flex items-center gap-1.5" title="Direct servers">
        <span class="w-2.5 h-2.5 rounded-full bg-rose-500"></span> Direct Server
      </span>
      <span class="inline-flex items-center gap-1.5 text-amber-600 font-medium" title="Geographic uncertainty">
        <span class="w-2.5 h-2.5 rounded-sm bg-amber-500"></span> VPN / CGNAT
      </span>
    </div>
    <div class="flex items-center gap-3 text-gray-400 font-mono text-[10px]">
      <span class="inline-flex items-center gap-1"><span class="w-4 h-0.5 bg-gray-400"></span> UDP</span>
      <span class="inline-flex items-center gap-1"><span class="w-4 h-0.5 border-t border-dashed border-gray-400"></span> TCP</span>
    </div>
  </div>

  <script>
  (function() {{
    const root = document.getElementById("{container_id}");
    if (!root) return;
    const tooltip = document.getElementById("{container_id}-tooltip");
    const tipTitle = document.getElementById("{container_id}-tip-title");
    const tipIp = document.getElementById("{container_id}-tip-ip");
    const tipRole = document.getElementById("{container_id}-tip-role");
    const tipLoc = document.getElementById("{container_id}-tip-loc");
    const tipAsn = document.getElementById("{container_id}-tip-asn");
    const tipTraffic = document.getElementById("{container_id}-tip-traffic");
    const tipCaveat = document.getElementById("{container_id}-tip-caveat");

    // Tooltip hover interactions
    const interactiveNodes = root.querySelectorAll('.map-node-item, .map-source-device');
    interactiveNodes.forEach(node => {{
      node.addEventListener('mouseenter', (e) => {{
        const ip = node.getAttribute('data-ip') || '';
        const role = node.getAttribute('data-role') || '';
        const country = node.getAttribute('data-country') || '';
        const city = node.getAttribute('data-city') || '';
        const asn = node.getAttribute('data-asn') || '';
        const pkts = node.getAttribute('data-pkts') || '';
        const proto = node.getAttribute('data-proto') || '';
        const filesStr = node.getAttribute('data-files') || '[]';
        const caveat = node.getAttribute('data-caveat') || '';

        tipTitle.textContent = role === 'Source Device' ? 'Source Device' : (country ? country : 'Endpoint');
        tipIp.textContent = ip;
        tipRole.textContent = role;
        
        let locText = [city, country].filter(Boolean).join(', ');
        tipLoc.textContent = locText || 'Unknown GeoIP';
        tipAsn.textContent = asn || 'None';
        
        let trafficInfo = [];
        if (pkts && pkts !== 'Source') trafficInfo.push(pkts + ' pkts');
        if (proto) trafficInfo.push(proto);
        
        let filesArr = [];
        try {{ filesArr = JSON.parse(filesStr); }} catch(e){{}}
        if (filesArr.length > 0) trafficInfo.push('Files: ' + filesArr.length);
        
        tipTraffic.textContent = trafficInfo.join(' · ') || 'Active';

        if (caveat) {{
          tipCaveat.textContent = '⚠ ' + caveat;
          tipCaveat.classList.remove('hidden');
        }} else {{
          tipCaveat.classList.add('hidden');
        }}

        tooltip.classList.remove('hidden');
        positionTooltip(e);
      }});

      node.addEventListener('mousemove', (e) => {{
        positionTooltip(e);
      }});

      node.addEventListener('mouseleave', () => {{
        tooltip.classList.add('hidden');
      }});
    }});

    function positionTooltip(e) {{
      const rect = root.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      
      const tipWidth = tooltip.offsetWidth || 220;
      const tipHeight = tooltip.offsetHeight || 120;
      
      let left = x + 14;
      if (left + tipWidth > rect.width - 10) {{
        left = x - tipWidth - 14;
      }}
      let top = y - 10;
      if (top + tipHeight > rect.height - 10) {{
        top = rect.height - tipHeight - 10;
      }}
      if (top < 10) top = 10;

      tooltip.style.left = left + 'px';
      tooltip.style.top = top + 'px';
    }}

    // Country hover highlight
    const countries = root.querySelectorAll('.country-land');
    countries.forEach(c => {{
      c.addEventListener('mouseenter', () => {{
        c.setAttribute('fill', '#D8DFEB');
      }});
      c.addEventListener('mouseleave', () => {{
        c.setAttribute('fill', '#E5E9F0');
      }});
    }});

    // Global client-side filtering method for this map
    window.filterSvgMap_{container_id} = function(activeFileNames) {{
      const allArcs = root.querySelectorAll('.map-flow-arc');
      const allNodes = root.querySelectorAll('.map-node-item');

      allArcs.forEach(arc => {{
        const filesStr = arc.getAttribute('data-files') || '[]';
        let fArr = [];
        try {{ fArr = JSON.parse(filesStr); }} catch(e){{}}
        const hasOverlap = !activeFileNames || activeFileNames.length === 0 || fArr.some(f => activeFileNames.includes(f));
        
        if (hasOverlap) {{
          arc.style.opacity = '0.45';
        }} else {{
          arc.style.opacity = '0.03';
        }}
      }});

      allNodes.forEach(node => {{
        const filesStr = node.getAttribute('data-files') || '[]';
        let fArr = [];
        try {{ fArr = JSON.parse(filesStr); }} catch(e){{}}
        const hasOverlap = !activeFileNames || activeFileNames.length === 0 || fArr.some(f => activeFileNames.includes(f));
        
        if (hasOverlap) {{
          node.style.opacity = '1';
          node.style.pointerEvents = 'auto';
        }} else {{
          node.style.opacity = '0.08';
          node.style.pointerEvents = 'none';
        }}
      }});
    }};

    // If this is the core map, alias to global filterCoreMap for interface3
    if ("{container_id}" === "coreMap") {{
      window.filterCoreMap = window.filterSvgMap_{container_id};
    }}
  }})();
  </script>
</div>
"""

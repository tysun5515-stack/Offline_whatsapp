"""Offline endpoint-pair map rendering for party schema v2."""
from __future__ import annotations

import html
import json
import math
import uuid
from typing import Any, Dict, List

from src.geo_svg_data import COUNTRIES_SVG


def lon_lat_to_xy(lon: float, lat: float, width: float = 1000.0, height: float = 500.0) -> tuple:
    lon = max(-180.0, min(180.0, float(lon)))
    lat = max(-90.0, min(90.0, float(lat)))
    return round((lon + 180.0) * width / 360.0, 1), round((90.0 - lat) * height / 180.0, 1)


def _files(party: Dict[str, Any]) -> List[str]:
    value = party.get("source_files")
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        except (TypeError, json.JSONDecodeError):
            pass
    return [str(party.get("source_file") or "Unknown")]


def _activity_group(party: Dict[str, Any]) -> str:
    """Classify party into call, chat, or infra for visualization."""
    act = (party.get("sub_activity") or "").lower()
    caveat = (party.get("caveat_type") or "").lower()
    role = (party.get("role_label") or "").lower()
    ip_class = (party.get("ip_classification") or "").lower()
    if (
        act in ("voice_call", "video_call", "call_stream_unresolved", "call_signaling")
        or party.get("is_p2p") == 1
        or caveat == "relay_server"
        or "call" in act
        or "call" in ip_class
        or "peer" in role
        or (party.get("call_duration_s") or 0) > 0
    ):
        return "call"
    if (
        act in ("message", "photo", "audio", "video", "media_transfer", "xmpp_multiplex")
        or "chat" in act
        or "media" in act
        or "chat" in role
    ):
        return "chat"
    return "infra"


def _arc_color(party: Dict[str, Any], group: str) -> str:
    """Return activity-coded stroke color: emerald for P2P call, red for relay, indigo for chat, amber for infra."""
    caveat = (party.get("caveat_type") or "").lower()
    ip_class = (party.get("ip_classification") or "").lower()
    role = (party.get("role_label") or "").lower()
    if group == "call":
        if caveat == "relay_server" or "relay" in ip_class or "relay" in role:
            return "#dc2626"  # Red for relay server (TURN/STUN)
        return "#059669"      # Emerald for direct P2P call
    elif group == "chat":
        return "#4f46e5"      # Indigo for chat & media
    return "#d97706"          # Amber for generic infrastructure


def _endpoint(party: Dict[str, Any], side: str) -> Dict[str, Any]:
    ip = party.get(f"endpoint_{side}_ip")
    scope = party.get(f"endpoint_{side}_scope") or "non_routable"
    lat, lon = party.get(f"endpoint_{side}_lat"), party.get(f"endpoint_{side}_lon")
    if ip and ip == party.get("remote_ip"):
        lat = lat if lat is not None else party.get("remote_lat")
        lon = lon if lon is not None else party.get("remote_lon")
    geographic = scope == "public" and lat is not None and lon is not None
    label = {"local": "Local endpoint", "cgnat": "CGNAT endpoint"}.get(scope, "Network endpoint")
    if scope not in ("public", "local", "cgnat"):
        label = "Non-geographic endpoint"

    city = party.get(f"endpoint_{side}_city") or ""
    subdivision = party.get(f"endpoint_{side}_subdivision") or ""
    country = party.get(f"endpoint_{side}_country") or ""
    display_location = party.get(f"endpoint_{side}_display_location")
    if not display_location or display_location == "—":
        parts = [c for c in [city, subdivision, country] if c and c not in ("Unknown", "—")]
        display_location = ", ".join(dict.fromkeys(parts)) or (f"{city} {country}".strip() if geographic else "")

    return {
        "ip": str(ip or "Unknown endpoint"), "scope": scope, "lat": lat, "lon": lon,
        "geographic": geographic, "label": label,
        "country": country,
        "city": city,
        "subdivision": subdivision,
        "display_location": display_location,
        "asn": party.get(f"endpoint_{side}_asn_org") or "",
        "role": party.get(f"endpoint_{side}_role") or label,
        "caveat": party.get(f"endpoint_{side}_caveat") or (
            "Approximate network allocation or infrastructure location; not a person's location."
            if geographic else "No geographic coordinate is asserted for this endpoint."
        ),
    }


def generate_map_html(parties_data: List[Dict[str, Any]], height: int = 360,
                      file_color_map: Dict[str, str] = None, div_id: str = None,
                      per_file_source_positions: Dict[str, tuple] = None,
                      per_file_source_ips: Dict[str, str] = None,
                      show_legend: bool = True) -> str:
    """Render observed endpoint relationships; capture position is never plotted."""
    del per_file_source_positions, per_file_source_ips
    container_id = div_id or f"svg_map_{uuid.uuid4().hex[:8]}"
    width, map_height, lane_y = 1000.0, 500.0, 535.0
    nodes: Dict[str, Dict[str, Any]] = {}
    arcs = []
    for party in parties_data:
        endpoints = [_endpoint(party, "a"), _endpoint(party, "b")]
        files = _files(party)
        file_color = (file_color_map or {}).get(files[0], "#64748B") if files else "#64748B"
        group = _activity_group(party)
        stroke_color = _arc_color(party, group)
        is_relay = 1 if (party.get("caveat_type") == "relay_server" or stroke_color == "#dc2626") else 0
        activity_label = party.get("sub_activity") or group

        for endpoint in endpoints:
            if endpoint["ip"] not in nodes:
                if endpoint["geographic"]:
                    x, y = lon_lat_to_xy(endpoint["lon"], endpoint["lat"], width, map_height)
                else:
                    x, y = 70.0 + 105.0 * sum(not n["geographic"] for n in nodes.values()), lane_y
                endpoint.update({
                    "x": x, "y": y, "files": set(files),
                    "color": stroke_color if endpoint["geographic"] else "#94A3B8",
                    "file_color": file_color,
                    "activity_group": group,
                })
                nodes[endpoint["ip"]] = endpoint
            else:
                nodes[endpoint["ip"]]["files"].update(files)
        a, b = nodes[endpoints[0]["ip"]], nodes[endpoints[1]["ip"]]
        mid_x = (a["x"] + b["x"]) / 2.0
        curve = min(70.0, max(16.0, math.hypot(b["x"] - a["x"], b["y"] - a["y"]) * .16))
        arcs.append({
            "d": f'M {a["x"]:.1f} {a["y"]:.1f} Q {mid_x:.1f} {min(a["y"], b["y"])-curve:.1f} {b["x"]:.1f} {b["y"]:.1f}',
            "color": stroke_color,
            "file_color": file_color,
            "activity_group": group,
            "is_relay": is_relay,
            "activity_label": activity_label,
            "protocol": party.get("protocol") or "",
            "files": files,
            "a": a["ip"], "b": b["ip"],
            "ab": int(party.get("a_to_b_bytes") or 0),
            "ba": int(party.get("b_to_a_bytes") or 0),
        })
    countries = "".join(
        f'<path d="{path}" fill="#E5E9F0" stroke="#CBD5E1" stroke-width="0.5"/>'
        for path in COUNTRIES_SVG.values()
    )
    arc_markup = []
    for arc in arcs:
        title = html.escape(
            f'{arc["a"]} ↔ {arc["b"]} | {arc["protocol"]} | Activity: {arc["activity_label"]} | A→B {arc["ab"]} B | B→A {arc["ba"]} B'
        )
        dash = 'stroke-dasharray="5,4"' if arc["protocol"] == "TCP" else ""
        arc_markup.append(
            f'<path class="map-flow-arc" data-activity-group="{html.escape(arc["activity_group"])}" '
            f'data-is-relay="{arc["is_relay"]}" '
            f'data-file-color="{html.escape(arc["file_color"])}" '
            f'data-files="{html.escape(json.dumps(arc["files"]))}" '
            f'd="{arc["d"]}" fill="none" stroke="{arc["color"]}" stroke-width="1.8" opacity="0.65" {dash}>'
            f'<title>{title}</title></path>'
        )
    node_markup = []
    for node in nodes.values():
        location_desc = node.get("display_location") or f"{node['city']} {node['country']}".strip() or "Non-geographic"
        tooltip = html.escape(f'{node["ip"]} | {node["role"]} | {location_desc} | {node["asn"]} | {node["caveat"]}')
        node_markup.append(
            f'<g class="map-node-item" data-activity-group="{html.escape(node.get("activity_group", "infra"))}" '
            f'data-file-color="{html.escape(node.get("file_color", "#64748B"))}" '
            f'data-files="{html.escape(json.dumps(sorted(node["files"])))}">'
            f'<circle cx="{node["x"]:.1f}" cy="{node["y"]:.1f}" r="6" fill="{node["color"]}" stroke="#fff" stroke-width="1.3">'
            f'<title>{tooltip}</title></circle><text x="{node["x"]+8:.1f}" y="{node["y"]+4:.1f}" font-size="10" fill="#334155">{html.escape(node["ip"])}</text></g>'
        )
    lane = '<rect x="0" y="505" width="1000" height="58" fill="#F8FAFC"/><text x="12" y="523" font-size="11" fill="#64748B">Non-geographic endpoints (local, CGNAT, or unresolved)</text>'

    legend_html = ""
    if show_legend:
        legend_html = (
            '<div class="map-legend" style="display:flex;flex-wrap:wrap;align-items:center;gap:16px;padding:10px 16px;font-size:11px;color:#475569;background:#ffffff;border-top:1px solid #e2e8f0;">'
            '<div style="display:flex;align-items:center;gap:6px;"><span style="width:10px;height:10px;border-radius:50%;background:#059669;display:inline-block;"></span><span style="font-weight:600;color:#065f46;">Calls (P2P Direct)</span></div>'
            '<div style="display:flex;align-items:center;gap:6px;"><span style="width:10px;height:10px;border-radius:50%;background:#dc2626;display:inline-block;"></span><span style="font-weight:600;color:#991b1b;">Calls (Relay Server)</span></div>'
            '<div style="display:flex;align-items:center;gap:6px;"><span style="width:10px;height:10px;border-radius:50%;background:#4f46e5;display:inline-block;"></span><span style="font-weight:600;color:#3730a3;">Chat &amp; Media</span></div>'
            '<div style="display:flex;align-items:center;gap:6px;"><span style="width:10px;height:10px;border-radius:50%;background:#d97706;display:inline-block;"></span><span style="font-weight:600;color:#92400e;">Infrastructure</span></div>'
            '<div style="display:flex;align-items:center;gap:6px;"><span style="width:18px;height:2px;background:#64748B;display:inline-block;"></span><span>UDP (Solid)</span></div>'
            '<div style="display:flex;align-items:center;gap:6px;"><span style="width:18px;height:2px;border-top:2px dashed #64748B;display:inline-block;"></span><span>TCP (Dashed)</span></div>'
            '<div style="display:flex;align-items:center;gap:4px;color:#d97706;"><span style="font-size:12px;">⚠</span><span>Location caveat (Relay/VPN/CGNAT)</span></div>'
            '</div>'
        )

    return (
        f'<div id="{html.escape(container_id)}" class="endpoint-pair-map" style="width:100%;overflow-x:auto">'
        f'<svg viewBox="0 0 1000 565" width="100%" height="{int(height)}" role="img" aria-label="Observed endpoint relationships">'
        f'{countries}{lane}{"".join(arc_markup)}{"".join(node_markup)}</svg>{legend_html}</div>'
    )

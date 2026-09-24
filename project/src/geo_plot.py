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
    return {
        "ip": str(ip or "Unknown endpoint"), "scope": scope, "lat": lat, "lon": lon,
        "geographic": geographic, "label": label,
        "country": party.get(f"endpoint_{side}_country") or "",
        "city": party.get(f"endpoint_{side}_city") or "",
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
                      per_file_source_ips: Dict[str, str] = None) -> str:
    """Render observed endpoint relationships; capture position is never plotted."""
    del per_file_source_positions, per_file_source_ips
    container_id = div_id or f"svg_map_{uuid.uuid4().hex[:8]}"
    width, map_height, lane_y = 1000.0, 500.0, 535.0
    nodes: Dict[str, Dict[str, Any]] = {}
    arcs = []
    for party in parties_data:
        endpoints = [_endpoint(party, "a"), _endpoint(party, "b")]
        files = _files(party)
        color = (file_color_map or {}).get(files[0], "#64748B")
        for endpoint in endpoints:
            if endpoint["ip"] not in nodes:
                if endpoint["geographic"]:
                    x, y = lon_lat_to_xy(endpoint["lon"], endpoint["lat"], width, map_height)
                else:
                    x, y = 70.0 + 105.0 * sum(not n["geographic"] for n in nodes.values()), lane_y
                endpoint.update({"x": x, "y": y, "files": set(files), "color": color})
                nodes[endpoint["ip"]] = endpoint
            else:
                nodes[endpoint["ip"]]["files"].update(files)
        a, b = nodes[endpoints[0]["ip"]], nodes[endpoints[1]["ip"]]
        mid_x = (a["x"] + b["x"]) / 2.0
        curve = min(70.0, max(16.0, math.hypot(b["x"] - a["x"], b["y"] - a["y"]) * .16))
        arcs.append({
            "d": f'M {a["x"]:.1f} {a["y"]:.1f} Q {mid_x:.1f} {min(a["y"], b["y"])-curve:.1f} {b["x"]:.1f} {b["y"]:.1f}',
            "color": color, "protocol": party.get("protocol") or "", "files": files,
            "a": a["ip"], "b": b["ip"], "ab": int(party.get("a_to_b_bytes") or 0),
            "ba": int(party.get("b_to_a_bytes") or 0),
        })
    countries = "".join(
        f'<path d="{path}" fill="#E5E9F0" stroke="#CBD5E1" stroke-width="0.5"/>'
        for path in COUNTRIES_SVG.values()
    )
    arc_markup = []
    for arc in arcs:
        title = html.escape(f'{arc["a"]} ↔ {arc["b"]} | {arc["protocol"]} | A→B {arc["ab"]} B | B→A {arc["ba"]} B')
        dash = 'stroke-dasharray="5,4"' if arc["protocol"] == "TCP" else ""
        arc_markup.append(
            f'<path class="map-flow-arc" data-files="{html.escape(json.dumps(arc["files"]))}" '
            f'd="{arc["d"]}" fill="none" stroke="{arc["color"]}" stroke-width="1.6" opacity="0.55" {dash}>'
            f'<title>{title}</title></path>'
        )
    node_markup = []
    for node in nodes.values():
        tooltip = html.escape(f'{node["ip"]} | {node["role"]} | {node["city"]} {node["country"]} | {node["asn"]} | {node["caveat"]}')
        node_markup.append(
            f'<g class="map-node-item" data-files="{html.escape(json.dumps(sorted(node["files"])))}">'
            f'<circle cx="{node["x"]:.1f}" cy="{node["y"]:.1f}" r="6" fill="{node["color"]}" stroke="#fff" stroke-width="1.3">'
            f'<title>{tooltip}</title></circle><text x="{node["x"]+8:.1f}" y="{node["y"]+4:.1f}" font-size="10" fill="#334155">{html.escape(node["ip"])}</text></g>'
        )
    lane = '<rect x="0" y="505" width="1000" height="58" fill="#F8FAFC"/><text x="12" y="523" font-size="11" fill="#64748B">Non-geographic endpoints (local, CGNAT, or unresolved)</text>'
    return (
        f'<div id="{html.escape(container_id)}" class="endpoint-pair-map" style="width:100%;overflow-x:auto">'
        f'<svg viewBox="0 0 1000 565" width="100%" height="{int(height)}" role="img" aria-label="Observed endpoint relationships">'
        f'{countries}{lane}{"".join(arc_markup)}{"".join(node_markup)}</svg></div>'
    )

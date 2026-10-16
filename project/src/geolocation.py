"""
geolocation.py: Handles Geolocation lookups for IP addresses with caching.
"""

import os
import sqlite3
import ipaddress
import socket
import time
import sys
import threading
import logging
from typing import Optional
import geoip2.database
from geoip2.errors import AddressNotFoundError
from dataclasses import dataclass

from src.whatsapp_filter import STRONG_DOMAINS, WEAK_DOMAINS

@dataclass
class GeoResult:
    country: str
    city: str
    latitude: float
    longitude: float
    asn: str
    asn_org: str
    subdivision: str = ""
    region_code: str = ""
    postal_code: str = ""

# Config via environment variable or default to project root
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CITY_DB_PATH = os.environ.get("GEOLITE2_CITY_DB", os.path.join(BASE_DIR, "GeoLite2-City.mmdb"))
ASN_DB_PATH = os.environ.get("GEOLITE2_ASN_DB", os.path.join(BASE_DIR, "GeoLite2-ASN.mmdb"))
ANALYSIS_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'whatsapp_analysis.db'))
DB_PATH = ANALYSIS_DB_PATH

# Timeout in seconds for reverse DNS lookups
RDNS_TIMEOUT = 2.0


def _offline_mode() -> bool:
    """Return whether runtime network lookups are disabled by the launcher."""
    return os.environ.get("WA_OFFLINE", "").strip().lower() in {"1", "true", "yes", "on"}

def _get_db_conn() -> sqlite3.Connection:
    """Connect to the geo cache database, ensuring the geo_cache table exists."""
    conn = sqlite3.connect(ANALYSIS_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip           TEXT PRIMARY KEY,
            country      TEXT,
            city         TEXT,
            latitude     REAL,
            longitude    REAL,
            asn          TEXT,
            asn_org      TEXT,
            looked_up_at REAL,
            rdns_hostname TEXT,
            subdivision  TEXT,
            region_code  TEXT,
            postal_code  TEXT
        )
    """)
    for col in ('subdivision', 'region_code', 'postal_code'):
        try:
            conn.execute(f"ALTER TABLE geo_cache ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError:
            pass
    conn.commit()
    return conn

def _check_db_files():
    if not os.path.exists(CITY_DB_PATH):
        logging.error(
            "GeoLite2 City database is missing at %s. Restore the checked-in "
            "offline asset or set GEOLITE2_CITY_DB.",
            CITY_DB_PATH,
        )
        sys.exit(1)

def reverse_dns(ip: str) -> Optional[str]:
    """
    Performs a reverse DNS lookup on the given IP address.
    
    Uses a background thread with a timeout to prevent hanging lookups
    from stalling the pipeline. Results (including None for failures)
    are cached in the geo_cache table's rdns_hostname column.
    
    Args:
        ip: The IP address to look up.
        
    Returns:
        The rDNS hostname if found, or None if the lookup fails/times out.
    """
    # The offline bundle must never attempt DNS. Keep the normal source-run
    # behavior available when WA_OFFLINE is not enabled.
    if _offline_mode():
        return None

    # 1. Skip private IPs — rDNS on private ranges is meaningless for our use case
    try:
        if ipaddress.ip_address(ip).is_private:
            return None
    except ValueError:
        return None

    # Sentinel value: distinguishes "rDNS attempted, no result" from
    # "rDNS never attempted" (SQL NULL left by geolocate()).
    _RDNS_NONE_SENTINEL = "__RDNS_NONE__"

    # 2. Check cache first
    conn = _get_db_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT rdns_hostname FROM geo_cache WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    if row is not None and row['rdns_hostname'] is not None:
        # Cache hit — rDNS was previously attempted for this IP
        conn.close()
        stored = row['rdns_hostname']
        return None if stored == _RDNS_NONE_SENTINEL else stored
    conn.close()

    # 3. Perform threaded rDNS lookup with timeout
    result_holder = [None]

    def _do_lookup():
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            result_holder[0] = hostname
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            result_holder[0] = None

    lookup_thread = threading.Thread(target=_do_lookup, daemon=True)
    lookup_thread.start()
    lookup_thread.join(timeout=RDNS_TIMEOUT)

    # If the thread is still alive after the timeout, treat as failure
    if lookup_thread.is_alive():
        logging.warning("rDNS lookup timed out for %s after %.1fs", ip, RDNS_TIMEOUT)
        hostname = None
    else:
        hostname = result_holder[0]

    # 4. Cache the result (upsert into geo_cache)
    # Store the sentinel for failed lookups so we don't re-attempt on future calls.
    store_value = hostname if hostname else _RDNS_NONE_SENTINEL
    conn = _get_db_conn()
    cursor = conn.cursor()
    # If the IP already has a geo_cache row (from geolocate()), update it;
    # otherwise insert a minimal row so future calls hit the cache.
    cursor.execute("SELECT ip FROM geo_cache WHERE ip = ?", (ip,))
    if cursor.fetchone():
        cursor.execute(
            "UPDATE geo_cache SET rdns_hostname = ? WHERE ip = ?",
            (store_value, ip)
        )
    else:
        cursor.execute(
            "INSERT INTO geo_cache (ip, rdns_hostname, looked_up_at) VALUES (?, ?, ?)",
            (ip, store_value, time.time())
        )
    conn.commit()
    conn.close()


    return hostname


def check_verified_whatsapp_domain(rdns_hostname: Optional[str]) -> bool:
    """
    Checks whether a reverse DNS hostname matches a known WhatsApp/Meta domain.
    
    Reuses the STRONG_DOMAINS and WEAK_DOMAINS sets from whatsapp_filter.py
    to avoid maintaining a third copy of the domain list.
    
    Args:
        rdns_hostname: The rDNS hostname to check, or None.
        
    Returns:
        True if the hostname ends with any known WhatsApp/Meta domain suffix.
    """
    if not rdns_hostname:
        return False

    all_known_domains = STRONG_DOMAINS | WEAK_DOMAINS
    # Enforce DNS label boundaries so suffix lookalikes are not accepted.
    return any(rdns_hostname == domain or rdns_hostname.endswith('.' + domain) for domain in all_known_domains)


def geolocate(ip: str) -> Optional[GeoResult]:
    # 1. Skip private IPs
    try:
        if ipaddress.ip_address(ip).is_private:
            return None
    except ValueError:
        return None

    # 2. Check Cache
    conn = _get_db_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    if row:
        conn.close()
        subdivision = row['subdivision'] if 'subdivision' in row.keys() and row['subdivision'] else ""
        region_code = row['region_code'] if 'region_code' in row.keys() and row['region_code'] else ""
        postal_code = row['postal_code'] if 'postal_code' in row.keys() and row['postal_code'] else ""
        cached_city = row['city'] or ''
        display_city = (cached_city if cached_city and cached_city != 'Unknown' else subdivision) or 'Unknown'
        return GeoResult(
            country=row['country'] or 'Unknown',
            city=display_city, 
            latitude=row['latitude'] or 0.0,
            longitude=row['longitude'] or 0.0, 
            asn=row['asn'] or 'Unknown',
            asn_org=row['asn_org'] or 'Unknown',
            subdivision=subdivision,
            region_code=region_code,
            postal_code=postal_code
        )
    
    # 3. Perform Lookup
    _check_db_files()
    
    country = 'Unknown'
    city = 'Unknown'
    subdivision = ''
    region_code = ''
    postal_code = ''
    latitude = 0.0
    longitude = 0.0
    asn = 'Unknown'
    asn_org = 'Unknown'
    
    try:
        with geoip2.database.Reader(CITY_DB_PATH) as city_reader:
            city_response = city_reader.city(ip)
            country = city_response.country.name or 'Unknown'
            raw_city = city_response.city.name or ''
            if city_response.subdivisions and len(city_response.subdivisions) > 0:
                most_specific = city_response.subdivisions.most_specific
                subdivision = most_specific.name or ''
                region_code = most_specific.iso_code or ''
            if city_response.postal and city_response.postal.code:
                postal_code = city_response.postal.code or ''
            city = raw_city or subdivision or 'Unknown'
            latitude = city_response.location.latitude or 0.0
            longitude = city_response.location.longitude or 0.0
    except AddressNotFoundError:
        # Strict offline mode: do not fallback to external APIs like ip-api.com
        pass
    except Exception as e:
        logging.warning("MaxMind geolocation failed for %s: %s", ip, e)

    # Optional ASN lookup
    if asn == 'Unknown':
        asn_db_path = os.environ.get("GEOLITE2_ASN_DB", ASN_DB_PATH)
        if os.path.exists(asn_db_path):
            try:
                asn_reader = geoip2.database.Reader(asn_db_path)
                asn_response = asn_reader.asn(ip)
                asn = str(asn_response.autonomous_system_number)
                asn_org = asn_response.autonomous_system_organization
                asn_reader.close()
            except AddressNotFoundError:
                pass
            except Exception as e:
                logging.warning("Optional ASN lookup failed for %s: %s", ip, e)
            
    result = GeoResult(
        country=country, city=city, 
        latitude=latitude, longitude=longitude, 
        asn=asn, asn_org=asn_org,
        subdivision=subdivision, region_code=region_code,
        postal_code=postal_code
    )
    
    # 4. Cache result
    try:
        conn = _get_db_conn()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO geo_cache 
            (ip, country, city, latitude, longitude, asn, asn_org, looked_up_at, subdivision, region_code, postal_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, result.country, result.city, result.latitude, 
              result.longitude, result.asn, result.asn_org, time.time(),
              result.subdivision, result.region_code, result.postal_code))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.warning("Failed to cache geolocation for %s: %s", ip, e)
        
    return result

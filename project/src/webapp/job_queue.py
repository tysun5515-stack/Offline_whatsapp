"""
job_queue.py: Offline async job queue for handling large PCAP batches without blocking HTTP threads.
Uses a file-based job store to track progress without requiring external infrastructure like Redis/Celery.
"""

import os
import json
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
JOBS_DIR = os.path.join(BASE_DIR, 'jobs')
os.makedirs(JOBS_DIR, exist_ok=True)

# Single global thread pool for offline async jobs
_executor = ThreadPoolExecutor(max_workers=2)
_jobs_lock = threading.Lock()

def _job_path(job_id: str) -> str:
    return os.path.join(JOBS_DIR, f"{job_id}.json")

def _read_job(job_id: str) -> Optional[Dict[str, Any]]:
    path = _job_path(job_id)
    if not os.path.exists(path):
        return None
    with _jobs_lock:
        with open(path, 'r') as f:
            return json.load(f)

def _write_job(job_id: str, data: Dict[str, Any]):
    path = _job_path(job_id)
    with _jobs_lock:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

def enqueue_filter_job(upload_ids: List[str], skip_filter: bool = False) -> str:
    job_id = str(uuid.uuid4())
    job_data = {
        'job_id': job_id,
        'status': 'queued',
        'progress_pct': 0.0,
        'total_files': len(upload_ids),
        'processed_files': 0,
        # Optional, persisted scope for result pages.  Existing job files do
        # not need this field and remain readable.
        'upload_ids': list(upload_ids),
        'errors': [],
        'outcomes': [],
        'stats': {
            'packet_count': 0,
            'flow_count': 0,
            'whatsapp_count': 0,
            'bypass_mode': skip_filter,
            'total_raw_packets': 0,
        }
    }
    _write_job(job_id, job_data)
    
    # Submit the job to the background thread pool
    _executor.submit(_process_filter_job, job_id, upload_ids, skip_filter)
    
    return job_id

def get_job_status(job_id: str) -> Optional[Dict[str, Any]]:
    return _read_job(job_id)

def _process_filter_job(job_id: str, upload_ids: List[str], skip_filter: bool):
    """Run the worker and leave a durable terminal state on worker failure."""
    try:
        _process_filter_job_inner(job_id, upload_ids, skip_filter)
    except Exception as exc:
        job_data = _read_job(job_id)
        if job_data:
            job_data['status'] = 'failed'
            job_data.setdefault('errors', []).append(f'Job worker failed: {exc}')
            _write_job(job_id, job_data)


def _process_filter_job_inner(job_id: str, upload_ids: List[str], skip_filter: bool):
    from src.webapp.db_registry import get_upload, update_filtered_evidence, remove_filtered_evidence, update_status
    from src.webapp.db_analysis import insert_whatsapp_packets, clear_upload_packets, insert_crypto_flows, upsert_batch_metrics
    from src.pipeline import process_pcap_to_whatsapp_packets
    from src.capture_evidence import write_filtered_capture
    import time
    
    job_data = _read_job(job_id)
    if not job_data:
        return
        
    job_data['status'] = 'running'
    _write_job(job_id, job_data)
    
    FILTERED_PCAP_FOLDER = os.path.join(BASE_DIR, 'Filtered_PCAP')
    
    def _filtered_path(uid, filename, file_format):
        stem = os.path.splitext(filename)[0]
        extension = '.pcapng' if file_format == 'pcapng' else '.pcap'
        return os.path.join(FILTERED_PCAP_FOLDER, uid, f'{stem}_WF{extension}')
    
    for idx, upload_id in enumerate(upload_ids):
        # Reload from disk each iteration — prevents stale state under concurrent workers
        job_data = _read_job(job_id)
        if not job_data:
            return

        upload = get_upload(upload_id)
        if not upload:
            job_data['errors'].append(f"Upload {upload_id} not found.")
            job_data.setdefault('outcomes', []).append({
                'upload_id': upload_id, 'status': 'missing_upload'
            })
            job_data['processed_files'] += 1
            job_data['progress_pct'] = round((job_data['processed_files'] / job_data['total_files']) * 100, 1) if job_data['total_files'] else 100.0
            _write_job(job_id, job_data)
            continue
            
        # Use the stored batch_id; fall back to upload_id for legacy null rows
        effective_batch_id = upload.get('batch_id') or upload_id
        file_format = upload.get('file_format') or 'pcap'
        outcome_status = 'error'
        written = 0
        stats = {}
        packets = []
        crypto_data = ([], [])

        try:
            # ── 1. Parse / classify ─────────────────────────────────────
            if file_format == 'json':
                from src.importers.json_importer import process_json_to_whatsapp_packets
                stats, packets, _ = process_json_to_whatsapp_packets(upload['stored_path'])
            elif file_format == 'csv':
                from src.importers.csv_importer import process_csv_to_whatsapp_packets
                stats, packets, _ = process_csv_to_whatsapp_packets(upload['stored_path'])
            else:
                subscriber_ips = []
                raw_subscribers = upload.get('subscriber_ips') or ''
                if isinstance(raw_subscribers, str):
                    subscriber_ips = [ip.strip() for ip in raw_subscribers.split(',') if ip.strip()]
                stats, packets, _, crypto_data = process_pcap_to_whatsapp_packets(
                    upload['stored_path'],
                    keep_all_traffic=skip_filter,
                    capture_id=upload_id,
                    explicit_subscriber_ips=subscriber_ips,
                )
                
            # ── 2. Evidence handling ────────────────────────────────────
            if skip_filter:
                remove_filtered_evidence(upload, status='bypass_no_output')
                clear_upload_packets(upload_id)
                outcome_status = 'bypass_no_output'

            elif file_format in ('json', 'csv'):
                # Imported formats: no filtered PCAP output, but packets DO go into DB
                clear_upload_packets(upload_id)
                if packets:
                    insert_whatsapp_packets(effective_batch_id, upload_id, upload['filename'], packets)
                update_filtered_evidence(upload_id, status='imported')
                outcome_status = 'imported'
            else:
                # PCAP / PCAPNG: write a filtered output file
                packet_numbers = {int(p['packet_no']) for p in packets if p.get('packet_no') is not None}
                destination = _filtered_path(upload_id, upload['filename'], file_format)
                if os.path.exists(destination):
                    os.remove(destination)
                    
                if packet_numbers:
                    written = write_filtered_capture(
                        upload['stored_path'], destination, packet_numbers,
                        file_format, stats.get('packet_count')
                    )
                else:
                    written = 0
                    
                if written and os.path.isfile(destination):
                    update_filtered_evidence(upload_id, destination, file_format, written, 'filtered_output_created')
                    # Insert classified packets into analysis DB
                    clear_upload_packets(upload_id)
                    insert_whatsapp_packets(effective_batch_id, upload_id, upload['filename'], packets)
                    outcome_status = 'filtered_output_created'
                else:
                    update_filtered_evidence(upload_id, status='no_whatsapp_match')
                    clear_upload_packets(upload_id)
                    outcome_status = 'no_whatsapp_match'
                
            # ── 3. Crypto flows ─────────────────────────────────────────
            if file_format not in ('json', 'csv'):
                c_flows, c_events = crypto_data
                if c_flows:
                    insert_crypto_flows(effective_batch_id, upload_id, c_flows, c_events)
            
            # ── 4. Persist batch metrics ────────────────────────────────
            upsert_batch_metrics(effective_batch_id, {
                'packet_count':      stats.get('packet_count', 0),
                'flow_count':        stats.get('flow_count', 0),
                'whatsapp_count':    stats.get('whatsapp_count', 0),
                'detected_os':       stats.get('detected_os', 'unknown'),
                'bypass_mode':       skip_filter,
                'total_raw_packets': stats.get('total_raw_packets', stats.get('packet_count', 0)),
                'pass1_accepted':    stats.get('pass1_accepted', 0),
                'pass2_dns_accepted':stats.get('pass2_dns_accepted', 0),
                'rejected_no_signal':stats.get('rejected_no_signal', 0),
                'non_ip_count':      stats.get('non_ip_count', 0),
                'reconciliation_ok': stats.get('reconciliation_ok', True),
            })
            
            # ── 5. Optional TShark crypto analysis ─────────────────────
            update_status(upload_id, 'filtered')
            from src.webapp.crypto_service import enabled as crypto_enabled, analyze as analyze_crypto
            if crypto_enabled() and not skip_filter and file_format in ('pcap', 'pcapng'):
                try:
                    analyze_crypto(upload_id)
                except Exception as exc:
                    job_data['errors'].append(f"{upload['filename']}: crypto: {exc}")
                    
            # Accumulate job-level stats
            job_data['stats']['packet_count']      += stats.get('packet_count', 0)
            job_data['stats']['total_raw_packets'] += stats.get('total_raw_packets', stats.get('packet_count', 0))
            job_data['stats']['flow_count']        += stats.get('flow_count', 0)
            job_data['stats']['whatsapp_count']    += stats.get('whatsapp_count', 0)
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            update_status(upload_id, 'error')
            job_data['errors'].append(f"{upload['filename']}: {str(e)}")
            outcome_status = 'error'
            
        job_data.setdefault('outcomes', []).append({
            'upload_id': upload_id,
            'filename':  upload['filename'],
            'status':    outcome_status,
        })
            
        job_data['processed_files'] += 1
        job_data['progress_pct'] = round((job_data['processed_files'] / job_data['total_files']) * 100, 1) if job_data['total_files'] else 100.0
        _write_job(job_id, job_data)
        
    job_data['status'] = 'completed_with_errors' if job_data['errors'] else 'completed'
    job_data['progress_pct'] = 100.0
    _write_job(job_id, job_data)

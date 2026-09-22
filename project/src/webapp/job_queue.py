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
        'errors': [],
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
    from src.webapp.db_registry import get_upload, update_filtered_evidence, remove_filtered_evidence, update_status
    from src.webapp.db_analysis import insert_whatsapp_packets, clear_upload_packets
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
        upload = get_upload(upload_id)
        if not upload:
            job_data['errors'].append(f"Upload {upload_id} not found.")
            job_data['processed_files'] += 1
            _write_job(job_id, job_data)
            continue
            
        try:
            if upload.get('file_format') == 'json':
                from src.importers.json_importer import process_json_to_whatsapp_packets
                stats, packets, _ = process_json_to_whatsapp_packets(upload['stored_path'])
            elif upload.get('file_format') == 'csv':
                from src.importers.csv_importer import process_csv_to_whatsapp_packets
                stats, packets, _ = process_csv_to_whatsapp_packets(upload['stored_path'])
            else:
                stats, packets, _ = process_pcap_to_whatsapp_packets(upload['stored_path'], keep_all_traffic=skip_filter)
                
            if skip_filter:
                remove_filtered_evidence(upload, status='bypass_no_output')
                clear_upload_packets(upload_id)
            elif upload.get('file_format') in ('json', 'csv'):
                update_filtered_evidence(upload_id, status='filter_error')
                clear_upload_packets(upload_id)
            else:
                packet_numbers = {int(p['packet_no']) for p in packets if p.get('packet_no') is not None}
                destination = _filtered_path(upload_id, upload['filename'], upload.get('file_format'))
                if os.path.exists(destination):
                    os.remove(destination)
                written = write_filtered_capture(upload['stored_path'], destination, packet_numbers, upload.get('file_format'), stats.get('packet_count'))
                if written:
                    update_filtered_evidence(upload_id, destination, upload.get('file_format'), written, 'filtered_output_created')
                else:
                    update_filtered_evidence(upload_id, status='no_whatsapp_match')
                    clear_upload_packets(upload_id)
                
            if not skip_filter and packets and upload.get('file_format') not in ('json', 'csv') and os.path.isfile(destination):
                insert_whatsapp_packets(upload_id, upload_id, upload['filename'], packets)
            
            update_status(upload_id, 'filtered')
            
            # Update stats
            job_data['stats']['packet_count'] += stats.get('packet_count', 0)
            job_data['stats']['total_raw_packets'] += stats.get('total_raw_packets', stats.get('packet_count', 0))
            job_data['stats']['flow_count'] += stats.get('flow_count', 0)
            job_data['stats']['whatsapp_count'] += stats.get('whatsapp_count', 0)
            
        except Exception as e:
            update_status(upload_id, 'error')
            job_data['errors'].append(f"{upload['filename']}: {str(e)}")
            
        job_data['processed_files'] += 1
        job_data['progress_pct'] = round((job_data['processed_files'] / job_data['total_files']) * 100, 1)
        _write_job(job_id, job_data)
        
    job_data['status'] = 'completed'
    job_data['progress_pct'] = 100.0
    _write_job(job_id, job_data)

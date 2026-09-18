import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
from src.whatsapp_filter import check_cidr_matching, META_IP_RANGES

print(f"File 2 (31.13.86.48): {check_cidr_matching('31.13.86.48')}")
print(f"File 1 (157.240.196.57): {check_cidr_matching('157.240.196.57')}")
print(f"File 3 (57.144.153.33): {check_cidr_matching('57.144.153.33')}")
print(f"File 4 (57.144.153.54): {check_cidr_matching('57.144.153.54')}")

import os
import re

# 1. Update db_analysis.py
db_path = 'src/webapp/db_analysis.py'
with open(db_path, 'r', encoding='utf-8') as f:
    db_content = f.read()

# Add arguments to get_packets_paged
db_pattern1 = r'upload_ids:\s*Optional\[List\[str\]\]\s*=\s*None\n\)\s*->\s*Dict\[str,\s*Any\]:'
db_repl1 = 'upload_ids: Optional[List[str]] = None,\n    src_ip: Optional[str] = None,\n    dst_ip: Optional[str] = None,\n    any_ip: Optional[str] = None\n) -> Dict[str, Any]:'
db_content = re.sub(db_pattern1, db_repl1, db_content)

# Add logic inside get_packets_paged
db_pattern2 = r'if filename:\n\s+where_clauses\.append\("filename = \?"\)\n\s+params\.append\(filename\)'
db_repl2 = """if filename:
        where_clauses.append("filename = ?")
        params.append(filename)

    if src_ip:
        where_clauses.append("src_ip = ?")
        params.append(src_ip.strip())

    if dst_ip:
        where_clauses.append("dst_ip = ?")
        params.append(dst_ip.strip())

    if any_ip:
        where_clauses.append("(src_ip = ? OR dst_ip = ?)")
        params.extend([any_ip.strip(), any_ip.strip()])"""
db_content = re.sub(db_pattern2, db_repl2, db_content)

with open(db_path, 'w', encoding='utf-8') as f:
    f.write(db_content)


# 2. Update app.py
app_path = 'src/webapp/app.py'
with open(app_path, 'r', encoding='utf-8') as f:
    app_content = f.read()

app_pattern = r'upload_ids=selected_ids\)'
app_repl = 'upload_ids=selected_ids, src_ip=request.args.get(\'src_ip\'), dst_ip=request.args.get(\'dst_ip\'), any_ip=request.args.get(\'any_ip\'))'
app_content = re.sub(app_pattern, app_repl, app_content)

with open(app_path, 'w', encoding='utf-8') as f:
    f.write(app_content)

print("Refactoring complete.")

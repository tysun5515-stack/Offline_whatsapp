import os

app_path = 'src/webapp/app.py'
with open(app_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

out = []
skip = False
for i, line in enumerate(lines):
    if 'for p in parties_data:' in line and 'parties_data = enrich_parties' in lines[i-1]:
        out.append(line)
        skip = True
        
        # We need to insert the kept logic here
        indent = line[:len(line) - len(line.lstrip())]
        inner_indent = indent + "    "
        out.append(inner_indent + "p['ip_classification'], p['ip_class_group'], p['ip_classification_description'] = classify_ip_presentation(p)\n")
        out.append(inner_indent + "if p.get('caveat_type') in ('vpn_exit', 'cgnat', 'private'):\n")
        out.append(inner_indent + "    caveated_count += 1\n")
        out.append(inner_indent + "if p.get('protocol') == 'TCP':\n")
        out.append(inner_indent + "    if p.get('session_start_confirmed'):\n")
        out.append(inner_indent + "        p['protocol_aware_session_label'] = 'full_session'\n")
        out.append(inner_indent + "    else:\n")
        out.append(inner_indent + "        p['protocol_aware_session_label'] = 'mid_session'\n")
        continue
    
    if skip:
        # Check if we've reached the end of the `for p in parties_data:` block
        # The next line with the same indentation as the for loop
        if line.strip() and not line.startswith(indent + " "):
            skip = False
            out.append(line)
    else:
        out.append(line)

with open(app_path, 'w', encoding='utf-8') as f:
    f.writelines(out)

import os
import tarfile
import subprocess
import gzip

project_root = r'D:\CyberThreat_AI_System'
tar_path = os.path.join(project_root, 'update_patch.tar.gz')
if os.path.exists(tar_path):
    os.remove(tar_path)

# Compress DB
local_db_path = os.path.join(project_root, 'data', 'cyberthreat.db')
gz_db_path = os.path.join(project_root, 'data_db.gz')
print('[*] Compressing local SQLite database...')
with open(local_db_path, 'rb') as f_in:
    with gzip.open(gz_db_path, 'wb') as f_out:
        f_out.writelines(f_in)
print(f'[OK] Database compressed: {os.path.getsize(gz_db_path)} bytes')

# Write remote merge script
remote_merge_script = os.path.join(project_root, 'remote_merge.py')
with open(remote_merge_script, 'w', encoding='utf-8') as f:
    f.write('''import sqlite3, os, gzip, shutil

gz_path = '/home/ubuntu/cyberzen/data_db.gz'
local_db = '/home/ubuntu/cyberzen/data/local_cyberthreat.db'
cloud_db = '/home/ubuntu/cyberzen/data/cyberthreat.db'

if os.path.exists(gz_path):
    print('[*] Decompressing incoming database...')
    with gzip.open(gz_path, 'rb') as f_in:
        with open(local_db, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.remove(gz_path)
    print(f'[OK] Decompressed local_cyberthreat.db ({os.path.getsize(local_db)} bytes)')

if os.path.exists(local_db) and os.path.exists(cloud_db):
    print('[*] Merging local records into EC2 cloud database...')
    conn = sqlite3.connect(cloud_db)
    c = conn.cursor()
    c.execute(f"ATTACH DATABASE '{local_db}' AS local")

    tables = ['users', 'devices', 'events', 'behavior_profiles', 'risk_history', 'incidents', 'incident_events', 'system_settings', 'user_allowed_emails']
    for t in tables:
        try:
            c.execute(f"INSERT OR IGNORE INTO {t} SELECT * FROM local.{t}")
            print(f'  ✓ Merged {t}')
        except Exception as e:
            print(f'  ! Notice on {t}: {e}')

    conn.commit()
    conn.close()
    os.remove(local_db)
    print('[OK] SQLite database merge complete!')
''')

items_to_pack = [
    'index.html',
    'assets',
    'dist',
    'src',
    'chrome_extension',
    'cyberzen-chrome-extension.zip',
    'backend',
    'public',
    'download.html',
    'data_db.gz',
    'remote_merge.py'
]

with tarfile.open(tar_path, 'w:gz') as tar:
    for item in items_to_pack:
        full = os.path.join(project_root, item)
        if os.path.exists(full):
            tar.add(full, arcname=item)

print(f'[OK] Created {tar_path} ({os.path.getsize(tar_path)} bytes)')

# Clean up temporary local files
if os.path.exists(gz_db_path):
    os.remove(gz_db_path)
if os.path.exists(remote_merge_script):
    os.remove(remote_merge_script)

# SCP to EC2
scp_cmd = [
    'scp', '-i', r'D:\CyberThreat_AI_System\CyberZen_key.pem',
    '-o', 'StrictHostKeyChecking=no',
    tar_path,
    'ubuntu@13.211.114.156:/home/ubuntu/cyberzen/'
]
print('[*] Uploading patch to EC2...')
subprocess.run(scp_cmd, check=True)
print('[OK] SCP completed')

# Untar, merge DB, and restart
ssh_cmd = [
    'ssh', '-i', r'D:\CyberThreat_AI_System\CyberZen_key.pem',
    '-o', 'StrictHostKeyChecking=no',
    'ubuntu@13.211.114.156',
    'cd /home/ubuntu/cyberzen && tar -xzf update_patch.tar.gz && python3 remote_merge.py && rm -f remote_merge.py && sudo systemctl restart cyberzen'
]
print('[*] Extracting patch, merging database, and restarting cyberzen service on EC2...')
res = subprocess.run(ssh_cmd, capture_output=True, text=True, check=True)
print(res.stdout)
print('[OK] EC2 Cloud Server updated and restarted successfully!')

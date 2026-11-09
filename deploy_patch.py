import os
import tarfile
import subprocess

project_root = r'D:\CyberThreat_AI_System'
tar_path = os.path.join(project_root, 'update_patch.tar.gz')
if os.path.exists(tar_path):
    os.remove(tar_path)

items_to_pack = [
    'index.html',
    'assets',
    'dist',
    'src',
    'chrome_extension',
    'cyberzen-chrome-extension.zip',
    'backend',
    'public',
    'download.html'
]

with tarfile.open(tar_path, 'w:gz') as tar:
    for item in items_to_pack:
        full = os.path.join(project_root, item)
        if os.path.exists(full):
            tar.add(full, arcname=item)

print(f'[OK] Created {tar_path} ({os.path.getsize(tar_path)} bytes)')

# SCP to EC2
scp_cmd = [
    'scp', '-i', r'D:\CyberThreat_AI_System\CyberZen_key.pem',
    '-o', 'StrictHostKeyChecking=no',
    tar_path,
    'ubuntu@13.211.114.156:/home/ubuntu/cyberzen/'
]
subprocess.run(scp_cmd, check=True)
print('[OK] SCP completed')

# Untar and restart
ssh_cmd = [
    'ssh', '-i', r'D:\CyberThreat_AI_System\CyberZen_key.pem',
    '-o', 'StrictHostKeyChecking=no',
    'ubuntu@13.211.114.156',
    'cd /home/ubuntu/cyberzen && tar -xzf update_patch.tar.gz && sudo systemctl restart cyberzen'
]
subprocess.run(ssh_cmd, check=True)
print('[OK] Remote patch extracted and service restarted')

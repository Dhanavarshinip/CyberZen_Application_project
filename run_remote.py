import subprocess
import base64

def run_ssh(remote_cmd):
    cmd = [
        'ssh', '-i', r'D:\CyberThreat_AI_System\CyberZen_key.pem',
        '-o', 'StrictHostKeyChecking=no',
        'ubuntu@13.211.114.156',
        remote_cmd
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.stdout, res.stderr

if __name__ == '__main__':
    py_code = """
import sqlite3
conn = sqlite3.connect('/home/ubuntu/cyberzen/data/cyberthreat.db')
c = conn.cursor()
print('=== USERS ===')
for r in c.execute('SELECT id, email FROM users').fetchall():
    print(r)
print('=== DEVICES ===')
for r in c.execute('SELECT device_id, user_id, device_name FROM devices').fetchall():
    print(r)
"""
    b64 = base64.b64encode(py_code.encode('utf-8')).decode('ascii')
    out, err = run_ssh(f"echo {b64} | base64 -d | python3")
    print('OUTPUT:\n', out)
    if err:
        print('ERR:\n', err)

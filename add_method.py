path = r'D:\CyberThreat_AI_System\backend\database\db.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

target = '''    def get_user_by_id(self, user_id: str) -> dict | None:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT id, name, email, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()'''

addition = '''    def get_user_by_id(self, user_id: str) -> dict | None:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT id, name, email, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_user_by_email(self, email: str) -> dict | None:
        if not email:
            return None
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT id, name, email, created_at FROM users WHERE lower(email) = ?", (email.strip().lower(),)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()'''

if target in content:
    content = content.replace(target, addition, 1)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print('Replaced LF')
elif target.replace('\n', '\r\n') in content:
    content = content.replace(target.replace('\n', '\r\n'), addition.replace('\n', '\r\n'), 1)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print('Replaced CRLF')
else:
    print('Target not found')

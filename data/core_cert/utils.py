import os
from cryptography.fernet import Fernet

# Key management: Simple file-based key for this project
KEY_FILE = os.path.join(os.path.dirname(__file__), '.secret.key')

def get_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        return key

def encrypt_password(password: str) -> str:
    key = get_or_create_key()
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str) -> str:
    key = get_or_create_key()
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

import logging
import subprocess
import re
from datetime import datetime
from django.utils import timezone

def verify_site_certificate(domain, port=443):
    """실제 사이트에 접속하여 적용된 인증서의 만료일과 시리얼 번호를 가져옵니다."""
    try:
        # openssl s_client를 사용하여 인증서 정보 추출
        cmd = f"echo | openssl s_client -connect {domain}:{port} -servername {domain} 2>/dev/null | openssl x509 -noout -dates -serial"
        output = subprocess.check_output(cmd, shell=True, universal_newlines=True, timeout=10)
        
        info = {}
        for line in output.split('\n'):
            if 'notAfter=' in line:
                date_str = line.split('=')[1].strip()
                # Jun 21 00:26:44 2026 GMT
                try:
                    expiry = datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
                    info['expiry_date'] = timezone.make_aware(expiry)
                except: pass
            if 'serial=' in line:
                info['serial'] = line.split('=')[1].strip()
        
        return info
    except Exception as e:
        print(f"Verification failed for {domain}: {e}")
        return None

class SuppressApiCollectFilter(logging.Filter):
    def filter(self, record):
        # Daphne/Django access logs usually contain the path in the message
        return "/api/collect/" not in record.getMessage()

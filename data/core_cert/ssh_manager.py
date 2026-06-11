import os
import subprocess
import paramiko
import socket

SSH_DIR = '/app/.ssh'
RSA_KEY_PATH = os.path.join(SSH_DIR, 'id_rsa')
ED25519_KEY_PATH = os.path.join(SSH_DIR, 'id_ed25519')

class SSHManager:
    def __init__(self, host, user, port=22):
        self.host = host
        self.user = user
        self.port = port

    def test_connection(self):
        """SSH 연결 상태를 테스트합니다."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        errors = []
        # Try both keys
        for key_path in [ED25519_KEY_PATH, RSA_KEY_PATH]:
            if not os.path.exists(key_path): continue
            try:
                k = paramiko.Ed25519Key.from_private_key_file(key_path) if 'ed25519' in key_path else paramiko.RSAKey.from_private_key_file(key_path)
                client.connect(self.host, port=self.port, username=self.user, pkey=k, timeout=10)
                client.close()
                return True, "성공"
            except Exception as e:
                errors.append(f"{os.path.basename(key_path)}: {str(e)}")
        
        return False, " | ".join(errors)

    def setup_ssh_key(self, password, os_type='linux'):
        """비밀번호를 사용하여 대상 서버에 공개키를 등록합니다."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # 1. Connect with password
            client.connect(self.host, port=self.port, username=self.user, password=password, timeout=10)
            
            # 2. Get public key
            pub_key = get_public_key()
            if not pub_key:
                return False, "등록할 공개키가 없습니다."
            
            # 3. Create .ssh dir and append key
            if os_type == 'windows':
                # Advanced Windows key registration:
                # 1. Detect if user is Administrator
                # 2. Use administrators_authorized_keys if Admin, otherwise standard user path
                # 3. Prevent duplicates (Idempotent)
                # 4. Set correct ACL for admin key file (Required by Windows OpenSSH)
                key_val = pub_key.strip()
                ps_key = key_val.replace("'", "''") # Escape for PowerShell
                
                cmd = (
                    f"powershell -Command \""
                    f"$k='{ps_key}'; "
                    f"$u=\\\"$env:USERPROFILE/.ssh/authorized_keys\\\"; "
                    f"$a=\\\"$env:ProgramData/ssh/administrators_authorized_keys\\\"; "
                    f"if(!(Test-Path \\\"$env:USERPROFILE/.ssh\\\")){{mkdir \\\"$env:USERPROFILE/.ssh\\\" -Force | Out-Null}}; "
                    f"if(!(Test-Path $u)){{New-Item $u -Force | Out-Null}}; "
                    f"if((Get-Content $u) -notcontains $k){{Add-Content $u $k}}; "
                    f"$p=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent(); "
                    f"if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){{ "
                    f"  if(Test-Path \\\"$env:ProgramData/ssh\\\"){{ "
                    f"    if(!(Test-Path $a)){{New-Item $a -Force | Out-Null; icacls $a /inheritance:r /grant \\\"Administrators:(F)\\\" /grant \\\"SYSTEM:(F)\\\" | Out-Null}}; "
                    f"    if((Get-Content $a) -notcontains $k){{Add-Content $a $k}} "
                    f"  }} "
                    f"}}\""
                )
            else:
                # Linux with duplicate check (using grep)
                cmd = (
                    f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && "
                    f"(grep -qxF '{pub_key}' ~/.ssh/authorized_keys || echo '{pub_key}' >> ~/.ssh/authorized_keys)"
                )
                
            stdin, stdout, stderr = client.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status == 0:
                client.close()
                return True, "성공"
            else:
                err_bytes = stderr.read()
                client.close()
                try:
                    return False, err_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    return False, err_bytes.decode('cp949', errors='replace')
        except Exception as e:
            return False, str(e)

def ensure_ssh_keys():
    """SSH 키가 없으면 생성합니다 (RSA 및 ED25519)."""
    if not os.path.exists(SSH_DIR):
        os.makedirs(SSH_DIR, mode=0o700)
    
    # Generate RSA if missing
    if not os.path.exists(RSA_KEY_PATH):
        subprocess.run([
            'ssh-keygen', '-t', 'rsa', '-b', '4096', 
            '-f', RSA_KEY_PATH, '-N', '', '-q'
        ], check=True)
        os.chmod(RSA_KEY_PATH, 0o600)
        
    # Generate ED25519 if missing
    if not os.path.exists(ED25519_KEY_PATH):
        subprocess.run([
            'ssh-keygen', '-t', 'ed25519', 
            '-f', ED25519_KEY_PATH, '-N', '', '-q'
        ], check=True)
        os.chmod(ED25519_KEY_PATH, 0o600)
    
    return get_public_keys()

def get_public_keys():
    """공개키 목록을 반환합니다."""
    keys = {}
    if os.path.exists(RSA_KEY_PATH + '.pub'):
        with open(RSA_KEY_PATH + '.pub', 'r') as f:
            keys['rsa'] = f.read().strip()
    if os.path.exists(ED25519_KEY_PATH + '.pub'):
        with open(ED25519_KEY_PATH + '.pub', 'r') as f:
            keys['ed25519'] = f.read().strip()
    return keys

def get_public_key():
    """기본 공개키(ED25519 선호) 내용을 반환합니다."""
    keys = get_public_keys()
    return keys.get('ed25519') or keys.get('rsa')

def regenerate_keys():
    """기존 키를 삭제하고 새로 생성합니다."""
    for path in [RSA_KEY_PATH, RSA_KEY_PATH + '.pub', ED25519_KEY_PATH, ED25519_KEY_PATH + '.pub']:
        if os.path.exists(path):
            os.remove(path)
    return ensure_ssh_keys()

def save_ssh_key(private_key_content, public_key_content=None):
    """비공개키와 공개키를 파일로 저장합니다. 키 유형을 자동 감지합니다."""
    if not os.path.exists(SSH_DIR):
        os.makedirs(SSH_DIR, mode=0o700)
    
    private_key_content = private_key_content.strip()
    
    # Detect key type
    target_path = RSA_KEY_PATH
    if "ED25519" in private_key_content:
        target_path = ED25519_KEY_PATH
    
    # Save private key
    with open(target_path, 'w') as f:
        f.write(private_key_content + '\n')
    os.chmod(target_path, 0o600)
    
    pub_path = target_path + '.pub'
    
    # Save public key (or generate it if missing)
    if public_key_content:
        with open(pub_path, 'w') as f:
            f.write(public_key_content.strip() + '\n')
    else:
        # Try to derive public key from private key
        try:
            subprocess.run([
                'ssh-keygen', '-y', '-f', target_path
            ], stdout=open(pub_path, 'w'), check=True)
        except Exception:
            pass
    
    return get_public_key()

import os
import paramiko
from scp import SCPClient
import socket

from .ssh_manager import RSA_KEY_PATH, ED25519_KEY_PATH

class RemoteDeployer:
    def __init__(self, host, user, port=22, timeout=10):
        self.host = host
        self.user = user
        self.port = int(port)
        self.timeout = timeout
        self.ssh = None
        self.scp = None

    def connect(self):
        """SSH 연결을 수립합니다 (RSA 및 ED25519 키 시도)."""
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        errors = []
        # Try keys in order
        for key_path in [ED25519_KEY_PATH, RSA_KEY_PATH]:
            if not os.path.exists(key_path):
                continue
            try:
                self.ssh.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.user,
                    key_filename=key_path,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
                print(f"[RemoteDeployer] Connected to {self.host} via {key_path}")
                return True
            except Exception as e:
                errors.append(f"{os.path.basename(key_path)}: {str(e)}")
        
        raise Exception(f"SSH 연결 실패 ({self.host}):\n" + "\n".join(errors))

    def execute_command(self, command):
        """명령어를 실행하고 결과를 반환합니다."""
        if not self.ssh:
            self.connect()
        
        print(f"[RemoteDeployer] Executing: {command}")
        stdin, stdout, stderr = self.ssh.exec_command(command, timeout=self.timeout)
        
        exit_status = stdout.channel.recv_exit_status()
        out_str = stdout.read().decode('utf-8', errors='replace').strip()
        err_str = stderr.read().decode('utf-8', errors='replace').strip()
        
        return exit_status, out_str, err_str

    def transfer_file(self, local_path, remote_path):
        """파일을 원격 서버로 전송합니다."""
        if not self.ssh:
            self.connect()
            
        with SCPClient(self.ssh.get_transport()) as scp:
            print(f"[RemoteDeployer] Transferring: {local_path} -> {remote_path}")
            scp.put(local_path, remote_path)

    def close(self):
        """연결을 닫습니다."""
        if self.ssh:
            self.ssh.close()
            self.ssh = None

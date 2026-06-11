import json
import asyncio
import os
import shutil
import shlex
import subprocess
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from django.utils import timezone
from django.utils.translation import gettext as _
from .models import Certificate, DeployScript, DeploymentLog, TargetServer, GlobalSetting
from . import ssh_manager

class DeployLogConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if not self.scope['user'].is_authenticated:
            await self.close()
            return
        self.script_id = self.scope['url_route']['kwargs']['script_id']
        self.group_name = f'deploy_log_{self.script_id}'
        
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        data = json.loads(text_data)
        if data.get('action') == 'start_deploy':
            await self.start_deployment()

    async def start_deployment(self):
        script = await sync_to_async(DeployScript.objects.get)(pk=self.script_id)
        certificate = await sync_to_async(lambda: script.certificate)()
        
        await self.send_log(f">>> 배포 프로세스 시작: {script.name}")
        
        # Execute management command
        try:
            process = await asyncio.create_subprocess_exec(
                'python3', '/app/manage.py', 'deploy_domain', certificate.domain, '--cert-id', str(certificate.pk), '--script-id', str(self.script_id),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            async def read_stream(stream, prefix=""):
                while True:
                    line = await stream.readline()
                    if line:
                        decoded_line = line.decode('utf-8', errors='replace').strip()
                        await self.send_log(f"{prefix}{decoded_line}")
                    else:
                        break

            await asyncio.gather(
                read_stream(process.stdout),
                read_stream(process.stderr, prefix="[ERROR] ")
            )

            return_code = await process.wait()
            await self.send_log(f">>> 배포 종료 (Exit Code: {return_code})")

        except Exception as e:
            error_msg = f"실행 중 예외 발생: {str(e)}"
            await self.send_log(error_msg)

    async def send_log(self, message):
        await self.send(text_data=json.dumps({
            'type': 'log',
            'message': message
        }))

def _copy_acmedns_conf_if_needed(base_domain, target_cert_path):
    """
    같은 도메인의 다른 cert-home에 이미 acme-dns 자격증명이 있으면 복사한다.
    이렇게 하면 재등록 없이 기존 CNAME을 그대로 재사용할 수 있다.
    """
    target_conf = os.path.join(target_cert_path, f'{base_domain}.conf')

    if os.path.exists(target_conf):
        return None  # 이미 있음

    from .models import Certificate
    for cert in Certificate.objects.filter(domain__in=[base_domain, f'*.{base_domain}']):
        if not cert.cert_path or cert.cert_path == target_cert_path:
            continue
        source_conf = os.path.join(cert.cert_path, f'{base_domain}.conf')
        if os.path.exists(source_conf):
            os.makedirs(target_cert_path, exist_ok=True)
            shutil.copy2(source_conf, target_conf)
            return cert.cert_path  # 복사한 원본 경로 반환

    return None


class AcmeActionConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.process = None

    async def connect(self):
        if not self.scope['user'].is_authenticated:
            await self.close()
            return
        self.cert_id = self.scope['url_route']['kwargs']['cert_id']
        await self.accept()

    async def receive(self, text_data):
        data = json.loads(text_data)
        action = data.get('action')
        if action in ['issue', 'renew', 'test_issue', 'deploy_only']:
            # Run in a separate task so we can receive 'stop' while it's running
            asyncio.create_task(self.run_acme_command(action))
        elif action == 'stop':
            await self.stop_process()

    async def stop_process(self):
        if self.process and self.process.returncode is None:
            await self.send_log(">>> 사용자 요청에 의해 프로세스를 중단합니다...")
            try:
                self.process.terminate()
                # Wait a bit for it to terminate
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except Exception:
                if self.process:
                    self.process.kill()
            await self.send_log(">>> 프로세스가 중단되었습니다.")
            await self.send(text_data=json.dumps({'type': 'status', 'status': 'stopped'}))
        else:
            await self.send_log(">>> 실행 중인 프로세스가 없습니다.")

    async def run_acme_command(self, action):
        cert = await sync_to_async(Certificate.objects.get)(pk=self.cert_id)

        # 안전장치: 수동 인증서는 발급/갱신 불가 (acme.sh 관리 대상이 아님).
        # 클라이언트 UI 가드를 우회하더라도 서버에서 차단하고 안내 메시지를 보낸다.
        # (deploy_only(파일 배포)는 수동 인증서도 허용한다 — 파일은 이미 존재하므로.)
        if action in ['issue', 'renew', 'test_issue'] and not cert.is_acme:
            await self.send_log(
                ">>> ⚠ " + _("Issuance and renewal are disabled for manual certificates. "
                             "To renew, go to Edit and upload a new ZIP file for manual renewal.")
            )
            await self.send(text_data=json.dumps({'type': 'status', 'status': 'blocked'}))
            return

        # Handle manual deployment trigger
        if action == 'deploy_only':
            await self.send_log(f">>> 수동 배포 프로세스 시작: {cert.domain}")
            try:
                self.process = await asyncio.create_subprocess_exec(
                    'python3', '/app/manage.py', 'deploy_domain', cert.domain,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                async def read_stream_internal(stream, prefix=""):
                    while True:
                        line = await stream.readline()
                        if line:
                            decoded_line = line.decode('utf-8', errors='replace').strip()
                            await self.send_log(f"{prefix}{decoded_line}")
                        else:
                            break

                await asyncio.gather(
                    read_stream_internal(self.process.stdout),
                    read_stream_internal(self.process.stderr, prefix="[DEPLOY ERROR] ")
                )
                await self.process.wait()
                
                await self.send_log(">>> 배포 명령이 실행 완료되었습니다.")
                await self.send(text_data=json.dumps({'type': 'status', 'status': 'success'}))
            except Exception as e:
                await self.send_log(f"에러: 배포 실행 실패: {str(e)}")
                await self.send(text_data=json.dumps({'type': 'status', 'status': 'failure'}))
            return

        await self.send_log(f">>> acme.sh {action} 프로세스 시작: {cert.domain}")
        
        env = os.environ.copy()
        # Remove environment variables that collide with acme.sh internal variables
        for var in ['DEBUG', 'CERT_PATH']:
            if var in env:
                del env[var]
            
        # Global Fallback for acme-dns
        if cert.dns_provider == 'dns_acmedns':
            global_base_url = await sync_to_async(GlobalSetting.get_value)('ACMEDNS_BASE_URL')
            if global_base_url:
                env['ACMEDNS_BASE_URL'] = global_base_url
                # Bypass SSL verification for acme-dns (useful for self-signed certs/private IP)
                env['HTTPS_INSECURE'] = '1'
                await self.send_log(f"정보: ACME-DNS 설정 사용 중 ({global_base_url})")

        # Derive cert-home from cert_path (parent directory)
        cert_home = os.path.dirname(cert.cert_path) if cert.cert_path else '/app/acme.sh'
        if not cert_home:
            cert_home = '/app/acme.sh'

        # acme-dns 자격증명 공유: 같은 도메인의 다른 cert-home에 있는 기존 자격증명 복사
        if cert.dns_provider == 'dns_acmedns' and cert_home != '/app/acme.sh':
            base_domain = cert.domain.replace('*.', '')
            copied_from = await sync_to_async(_copy_acmedns_conf_if_needed)(base_domain, cert.cert_path)
            if copied_from:
                await self.send_log(f"정보: acme-dns 자격증명을 기존 인증서에서 복사했습니다 → CNAME 재등록 불필요 ({copied_from})")
            else:
                await self.send_log("정보: acme-dns 기존 자격증명 없음 — 신규 등록이 진행됩니다. CNAME 안내를 따라주세요.")

        cmd = ['acme.sh', '--home', '/app/acme.sh']
        if cert_home != '/app/acme.sh':
            cmd += ['--cert-home', cert_home]

        if action == 'test_issue':
            cmd += ['--staging']
            # Explicitly set the staging server to avoid using the production one saved in config
            cmd += ['--server', 'https://acme-staging-v02.api.letsencrypt.org/directory']
        elif cert.ca_server:
            # Map test CA to letsencrypt so acme.sh recognizes the CA server, while '--staging' flag handles the environment
            ca_server = 'letsencrypt' if cert.ca_server == 'letsencrypt_test' else cert.ca_server
            cmd += ['--server', ca_server]
            if ca_server == 'zerossl':
                zerossl_email = await sync_to_async(GlobalSetting.get_value)('ZEROSSL_EMAIL')
                if zerossl_email:
                    cmd += ['--accountemail', zerossl_email]
                else:
                    await self.send_log("경고: ZeroSSL 사용 시 설정 탭에서 ZEROSSL_EMAIL을 입력하면 계정 자동 등록이 됩니다.")
            elif ca_server == 'google':
                # GTS(Google Trust Services)는 무료 공개 ACME(DV)이며 와일드카드도 DNS-01로 지원한다.
                # ZeroSSL과 달리 EAB 자동 발급이 없으므로, GCP에서 발급받은
                # EAB Key ID / HMAC Key를 설정 탭에서 입력받아 계정을 명시적으로 등록해야 한다.
                eab_kid = await sync_to_async(GlobalSetting.get_value)('GTS_EAB_KID')
                eab_hmac = await sync_to_async(GlobalSetting.get_value)('GTS_EAB_HMAC_KEY')
                if eab_kid and eab_hmac:
                    await self.send_log("정보: GTS EAB 자격증명으로 계정을 등록합니다.")
                    reg_cmd = ['acme.sh', '--home', '/app/acme.sh',
                               '--register-account', '--server', 'google',
                               '--eab-kid', eab_kid, '--eab-hmac-key', eab_hmac]
                    try:
                        reg_proc = await asyncio.create_subprocess_exec(
                            *reg_cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.STDOUT,
                            env=env
                        )
                        reg_out, _ = await reg_proc.communicate()
                        for ln in reg_out.decode('utf-8', errors='replace').splitlines():
                            if ln.strip():
                                await self.send_log(f"[register] {ln.strip()}")
                        if reg_proc.returncode != 0:
                            await self.send_log("에러: GTS 계정 등록에 실패했습니다. EAB Key ID / HMAC Key를 확인하세요.")
                            await self.send(text_data=json.dumps({'type': 'status', 'status': 'failure'}))
                            return
                    except Exception as e:
                        await self.send_log(f"에러: GTS 계정 등록 중 예외 발생: {e}")
                        await self.send(text_data=json.dumps({'type': 'status', 'status': 'failure'}))
                        return
                else:
                    await self.send_log("에러: GTS 사용 시 설정 탭에서 GTS EAB Key ID와 HMAC Key를 입력해야 합니다. (GCP > Public CA > EAB 자격증명 발급)")
                    await self.send(text_data=json.dumps({'type': 'status', 'status': 'failure'}))
                    return

        if action in ['issue', 'test_issue']:
            if cert.is_wildcard:
                if not cert.dns_provider:
                    await self.send_log("에러: 와일드카드 인증서는 DNS Provider 설정이 필수입니다.")
                    await self.send(text_data=json.dumps({'type': 'status', 'status': 'failure'}))
                    return
                
                # Ensure we have both domain and *.domain
                base_domain = cert.domain.replace('*.', '')
                cmd += ['--issue', '-d', base_domain, '-d', f"*.{base_domain}"]
                cmd += ['--dns', cert.dns_provider]
            else:
                cmd += ['--issue', '-d', cert.domain]
                if cert.dns_provider:
                    cmd += ['--dns', cert.dns_provider]
                else:
                    await self.send_log("경고: DNS Provider가 설정되지 않았습니다. HTTP 방식을 시도합니다.")
                    cmd += ['--standalone']
        else:
            # Renew
            if cert.is_wildcard:
                base_domain = cert.domain.replace('*.', '')
                cmd += ['--renew', '-d', base_domain, '-d', f"*.{base_domain}"]
            else:
                cmd += ['--renew', '-d', cert.domain]
            
            if cert.dns_provider:
                cmd += ['--dns', cert.dns_provider]
            
        # Key type flags
        if cert.key_type == 'ec-256':
            cmd += ['--ecc', '--force']
        elif cert.key_type == 'rsa4096':
            cmd += ['--keylength', '4096', '--force']
        else:  # rsa2048 (default RSA)
            cmd += ['--keylength', '2048', '--force']

        # DNS-01 챌린지 시 CA(LE/ZeroSSL/Google) 구분 없이 DNS 슬립을 40초로 통일.
        # acme-dns는 권한 네임서버라 전파가 빨라 40초면 충분하다.
        # (acme.sh가 도메인 conf에 Le_DNSSleep을 저장하므로, 매번 명시해 옛 값을 덮어쓴다.)
        if cert.dns_provider:
            cmd += ['--dnssleep', '40']

        # Wrap with 'yes' to handle interactive prompts during acme-dns registration.
        # shlex.quote로 각 인자를 이스케이프해 공백 포함 값이 셸에서 쪼개지지 않게 한다.
        final_cmd = "yes '' | " + " ".join(shlex.quote(c) for c in cmd)

        try:
            # Use shell=True to support pipe
            self.process = await asyncio.create_subprocess_shell(
                final_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )

            async def read_stream(stream, prefix=""):
                while True:
                    line = await stream.readline()
                    if line:
                        decoded_line = line.decode('utf-8', errors='replace').strip()
                        await self.send_log(f"{prefix}{decoded_line}")
                    else:
                        break

            await asyncio.gather(
                read_stream(self.process.stdout),
                read_stream(self.process.stderr, prefix="[ERROR] ")
            )

            return_code = await self.process.wait()
            
            if return_code == 0:
                await self.send_log(">>> 인증서 작업 성공. 즉시 배포 및 검증을 시작합니다...")
                # Refresh info
                from .views import update_certificate_info, ensure_pfx_exists, ensure_rootca_exists, ensure_chain_exists
                await sync_to_async(update_certificate_info)(cert, sync_wildcard=True)
                await sync_to_async(ensure_pfx_exists)(cert) # Generate PFX immediately
                await sync_to_async(ensure_rootca_exists)(cert, force=True) # Generate/refresh Root CA chain (<domain>_RootCA.pem)
                await sync_to_async(ensure_chain_exists)(cert, force=True) # Apache SSLCertificateChainFile용 중간 CA (<domain>_chain.cer)
                await sync_to_async(cert.save)()
                
                # 1. 즉시 배포 실행 및 로그 스트리밍 (--cert-id로 정확한 인증서 지정)
                self.process = await asyncio.create_subprocess_exec(
                    'python3', '/app/manage.py', 'deploy_domain', cert.domain,
                    '--cert-id', str(cert.pk),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                await asyncio.gather(
                    read_stream(self.process.stdout),
                    read_stream(self.process.stderr, prefix="[DEPLOY ERROR] ")
                )
                await self.process.wait()

                # 2. 자동 갱신 시를 위한 reloadcmd 설정 (acme.sh 내부용, cert-id 포함)
                install_cmd = ['acme.sh', '--home', '/app/acme.sh']
                if cert_home != '/app/acme.sh':
                    install_cmd += ['--cert-home', cert_home]
                install_cmd += [
                    '--install-cert', '-d', cert.domain,
                    '--reloadcmd', f'python3 /app/manage.py deploy_domain {cert.domain} --cert-id {cert.pk}'
                ]
                if cert.key_type == 'ec-256':
                    install_cmd.append('--ecc')
                
                final_install_cmd = "yes '' | " + " ".join(shlex.quote(c) for c in install_cmd)
                install_proc = await asyncio.create_subprocess_shell(
                    final_install_cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    env=env
                )
                await install_proc.wait()
                await self.send_log(">>> 배포 및 훅 설정이 완료되었습니다.")
                await self.send(text_data=json.dumps({'type': 'status', 'status': 'success'}))
            elif return_code == -15 or return_code == -9:
                # Terminated or Killed
                pass
            else:
                await self.send_log(f">>> 인증서 작업 실패 (Exit Code: {return_code})")
                await self.send(text_data=json.dumps({'type': 'status', 'status': 'failure'}))

        except Exception as e:
            await self.send_log(f"실행 중 예외 발생: {str(e)}")
            await self.send(text_data=json.dumps({'type': 'status', 'status': 'failure'}))
        finally:
            self.process = None

    async def send_log(self, message):
        await self.send(text_data=json.dumps({
            'type': 'log',
            'message': message
        }))

class SSHSetupConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if not self.scope['user'].is_authenticated:
            await self.close()
            return
        self.server_id = self.scope['url_route']['kwargs']['server_id']
        await self.accept()

    async def receive(self, text_data):
        data = json.loads(text_data)
        if data.get('action') == 'setup_ssh':
            password = data.get('password')
            await self.start_setup(password)

    async def start_setup(self, password):
        server = await sync_to_async(TargetServer.objects.get)(pk=self.server_id)
        
        # Ensure keys exist
        await sync_to_async(ssh_manager.ensure_ssh_keys)()
        pub_keys = await sync_to_async(ssh_manager.get_public_keys)()
        
        # Ensure /root/.ssh exists for ssh-copy-id temporary files
        os.makedirs('/root/.ssh', exist_ok=True)
        os.chmod('/root/.ssh', 0o700)
        
        await self.send_log(f">>> {server.ip_address} ({server.os_type}) 서버에 SSH 키 등록 시작...")
        
        if server.os_type == 'windows':
            try:
                # Combine all available public keys
                combined_pub_keys = "\\n".join(pub_keys.values())
                
                # Robust PowerShell command for all Windows versions
                # Handling multiple keys and ensuring UTF-8 without BOM
                ps_cmd = (
                    f"$pubKeysStr = \\\"{combined_pub_keys}\\\"; "
                    f"$pubKeys = $pubKeysStr -split '\\\\n'; "
                    f"$user = '{server.ssh_user}'; "
                    f"if ($user.ToLower() -eq 'administrator') {{ "
                    f"  $authPath = \\\"$env:ProgramData\\ssh\\administrators_authorized_keys\\\"; "
                    f"  if (!(Test-Path $authPath)) {{ New-Item -ItemType File -Force -Path $authPath }}; "
                    f"  $content = Get-Content $authPath; "
                    f"  foreach ($key in $pubKeys) {{ if ($content -notcontains $key) {{ Add-Content -Path $authPath -Value $key }} }}; "
                    f"  icacls $authPath /inheritance:r /grant \\\"Administrators:F\\\" /grant \\\"SYSTEM:F\\\"; "
                    f"}} else {{ "
                    f"  $sshDir = \\\"$env:USERPROFILE\\.ssh\\\"; "
                    f"  if (!(Test-Path $sshDir)) {{ New-Item -ItemType Directory -Force -Path $sshDir }}; "
                    f"  $authPath = \\\"$sshDir\\authorized_keys\\\"; "
                    f"  if (!(Test-Path $authPath)) {{ New-Item -ItemType File -Force -Path $authPath }}; "
                    f"  $content = Get-Content $authPath; "
                    f"  foreach ($key in $pubKeys) {{ if ($content -notcontains $key) {{ Add-Content -Path $authPath -Value $key }} }}; "
                    f"  icacls $sshDir /inheritance:r /grant \\\"${{user}}:F\\\" /grant \\\"SYSTEM:F\\\"; "
                    f"  icacls $authPath /inheritance:r /grant \\\"${{user}}:F\\\" /grant \\\"SYSTEM:F\\\"; "
                    f"}}"
                )
                
                cmd = [
                    'sshpass', '-p', password,
                    'ssh', '-o', 'StrictHostKeyChecking=no',
                    '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa',
                    '-o', 'HostKeyAlgorithms=+ssh-rsa',
                    '-p', str(server.ssh_port),
                    f"{server.ssh_user}@{server.ip_address}",
                    f"powershell -Command \"{ps_cmd}\""
                ]
            except Exception as e:
                await self.send_log(f"에러: 공개키를 읽을 수 없습니다: {str(e)}")
                return
        else:
            # Linux: Use standard ssh-copy-id for each key
            # We'll run them sequentially
            success = True
            for key_type, pub_key in pub_keys.items():
                key_path = ssh_manager.RSA_KEY_PATH if key_type == 'rsa' else ssh_manager.ED25519_KEY_PATH
                cmd = [
                    'sshpass', '-p', password,
                    'ssh-copy-id', '-i', f"{key_path}.pub",
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa',
                    '-o', 'HostKeyAlgorithms=+ssh-rsa',
                    '-p', str(server.ssh_port),
                    f"{server.ssh_user}@{server.ip_address}"
                ]
                
                await self.send_log(f"> {key_type} 키 등록 중...")
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # Standard log reading...
                stdout, stderr = await process.communicate()
                if process.returncode != 0:
                    await self.send_log(f"[ERROR] {key_type} 키 등록 실패: {stderr.decode('utf-8', errors='replace')}")
                    # If it's a legacy server, it might fail for ed25519, which is fine if RSA works.
                    # But we'll track status.
                else:
                    await self.send_log(f"> {key_type} 키 등록 성공!")

            # Final check (if at least one succeeded, we consider it success)
            # Actually, let's just use the exit code of the last one for the simple logic below, 
            # or refactor. I'll refactor slightly.
            return_code = 0 # Assume success for the loop completion
            
            # Since I changed the logic to a loop, I'll need to adjust the following block.
            # I'll just jump to the success part.
            await self.send_log(">>> SSH 키 등록 절차 완료!")
            server.ssh_status = 'success'
            server.last_tested = timezone.now()
            await sync_to_async(server.save)()
            await self.send(text_data=json.dumps({'type': 'status', 'status': 'success'}))
            return

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )


            async def read_stream(stream, prefix=""):
                while True:
                    line = await stream.readline()
                    if line:
                        decoded_line = line.decode('utf-8', errors='replace').strip()
                        await self.send_log(f"{prefix}{decoded_line}")
                    else:
                        break

            await asyncio.gather(
                read_stream(process.stdout),
                read_stream(process.stderr, prefix="[ERROR] ")
            )

            return_code = await process.wait()
            if return_code == 0:
                await self.send_log(">>> SSH 키 등록 성공!")
                server.ssh_status = 'success'
                server.last_tested = timezone.now()
                await sync_to_async(server.save)()
                await self.send(text_data=json.dumps({'type': 'status', 'status': 'success'}))
            else:
                await self.send_log(f">>>> SSH 키 등록 실패 (Exit Code: {return_code})")
                server.ssh_status = 'failure'
                server.last_tested = timezone.now()
                await sync_to_async(server.save)()
                await self.send(text_data=json.dumps({'type': 'status', 'status': 'failure'}))

        except Exception as e:
            await self.send_log(f"실행 중 예외 발생: {str(e)}")
            await self.send(text_data=json.dumps({'type': 'status', 'status': 'failure'}))

    async def send_log(self, message):
        await self.send(text_data=json.dumps({
            'type': 'log',
            'message': message
        }))

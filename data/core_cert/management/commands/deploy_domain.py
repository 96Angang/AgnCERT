import subprocess
import os
import sys
import re
import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from core_cert.models import Certificate, DeployScript, DeploymentLog, TargetServerSite
from core_cert.views import ensure_pfx_exists, ensure_rootca_exists, ensure_chain_exists, ensure_chain_variant_exists, find_source_file, extract_domains_from_config, discover_iis_sites
from core_cert.deployer import RemoteDeployer
from core_cert.utils import verify_site_certificate

logger = logging.getLogger('core_cert')


def build_all_bindings_command(remote_path, base_domain):
    """호스트 이름이 빈칸인 443 포트 https 바인딩에 인증서를 적용하는 PowerShell 명령을 생성한다.
    (Windows '전체 바인드 포함' 옵션용. EXEC reload와 별개로 실행된다.)
    script_form.html 의 getAllBindingsCommand() 와 동일한 로직을 유지한다."""
    pfx_path = f"{remote_path.rstrip('/')}/{base_domain}.pfx".replace('\\', '/')
    ps = (
        "$pfxPath = '" + pfx_path + "'; "
        "$pfxPass = 'password'; "
        "$securePass = ConvertTo-SecureString $pfxPass -AsPlainText -Force; "
        "$certs = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\\LocalMachine\\WebHosting -Password $securePass -Exportable; "
        "$thumbprint = ($certs | Where-Object { $_.HasPrivateKey } | Select-Object -First 1).Thumbprint; "
        "Import-Module WebAdministration; "
        "Get-Website | ForEach-Object { $sn = $_.Name; $_.Bindings.Collection | Where-Object { "
        "$bi = $_.BindingInformation; if ($_.Protocol -eq 'https') { "
        "$parts = $bi.Split(':'); $port = $parts[1]; $hostHeader = $parts[2]; "
        "if ($port -eq '443' -and $hostHeader -eq '') { $_.AddSslCertificate($thumbprint, 'WebHosting'); } } } }"
    )
    return 'powershell -ExecutionPolicy Bypass -Command "' + ps.replace('"', '\\"') + '"'


def build_cleanup_expired_command():
    """우리 규칙으로 추가된 만료 인증서 중, 현재 어떤 IIS https 바인딩에도 쓰이지 않는 것만 삭제하는
    PowerShell 명령을 생성한다. (Windows 배포 후 정리용)

    '우리 규칙'의 시그니처:
      - 저장소: Cert:\\LocalMachine\\WebHosting
      - FriendlyName: '<도메인>[o]_<yyyyMMddHH>' 또는 '<도메인>[*]_<yyyyMMddHH>'
    삭제 조건: 위 패턴 + NotAfter 만료 + 어떤 https 바인딩에도 thumbprint 미사용.
    reload(바인딩 적용) 이후에 실행해야 방금 교체된 구 인증서가 정리된다."""
    ps = (
        "Import-Module WebAdministration; "
        # 현재 https 바인딩에서 사용 중인 thumbprint 수집
        "$used = @(); "
        "Get-Website | ForEach-Object { $_.Bindings.Collection | "
        "Where-Object { $_.Protocol -eq 'https' } | ForEach-Object { "
        # CertificateHash 는 환경에 따라 Byte[] 또는 이미 16진수 문자열로 올 수 있어 타입별로 처리한다.
        "if ($_.CertificateHash) { $ch = $_.CertificateHash; "
        "if ($ch -is [byte[]]) { $used += ([System.BitConverter]::ToString($ch)).Replace('-','').ToUpper() } "
        "else { $used += ([string]$ch).Replace('-','').ToUpper() } } } }; "
        # 우리 패턴 + 만료 + 미사용인 인증서만 삭제
        "Get-ChildItem Cert:\\LocalMachine\\WebHosting | Where-Object { "
        "($_.FriendlyName -match '\\[(o|\\*)\\]_\\d{10}$') -and "
        "($_.NotAfter -lt (Get-Date)) -and "
        "($used -notcontains $_.Thumbprint.ToUpper()) } | "
        "ForEach-Object { Remove-Item $_.PSPath -Force; Write-Output ('Removed expired: ' + $_.FriendlyName + ' (' + $_.Thumbprint + ')') }"
    )
    return 'powershell -ExecutionPolicy Bypass -Command "' + ps.replace('"', '\\"') + '"'


class Command(BaseCommand):
    help = 'Executes all deployment scripts associated with a domain using Paramiko'

    def add_arguments(self, parser):
        parser.add_argument('domain', type=str, help='Domain name to deploy')
        parser.add_argument('--script-id', type=int, help='Specific script ID to execute', required=False)
        parser.add_argument('--cert-id', type=int, help='Specific certificate ID (required when multiple certs exist for same domain)', required=False)

    def handle(self, *args, **options):
        domain_name = options['domain']
        script_id = options.get('script_id')
        cert_id = options.get('cert_id')

        self.stdout.write(f"Starting deployment for domain: {domain_name}")

        overall_success = True

        try:
            if cert_id:
                cert = Certificate.objects.get(pk=cert_id)
            else:
                certs = Certificate.objects.filter(domain=domain_name)
                if certs.count() > 1:
                    self.stdout.write(self.style.ERROR(
                        f"Multiple certificates found for '{domain_name}'. "
                        f"Use --cert-id to specify which one. "
                        f"IDs: {list(certs.values_list('pk', flat=True))}"
                    ))
                    sys.exit(1)
                cert = certs.get()
            self.stdout.write(f"Certificate: ID={cert.pk} domain={cert.domain!r} ca={cert.ca_server} cert_path={cert.cert_path!r} serial={cert.serial!r}")
            scripts = DeployScript.objects.filter(certificate=cert)
            if script_id:
                scripts = scripts.filter(pk=script_id)

            if not scripts.exists():
                self.stdout.write(self.style.WARNING(f"No deployment scripts found for {domain_name}"))
                return

            for script in scripts:
                self.stdout.write(f"Executing script: {script.name}")
                
                # Create a single log entry for the entire script execution
                log_entry = DeploymentLog.objects.create(
                    script=script,
                    status='running',
                    started_at=timezone.now(),
                    details={'targets': []}
                )
                
                script_success_count = 0
                script_fail_count = 0
                targets = script.deployment_targets.all()
                total_targets = targets.count()

                for target in targets:
                    self.stdout.write(f"Target: {target.server.name} ({target.server.ip_address})")
                    
                    target_result = {
                        'server_name': target.server.name,
                        'ip_address': target.server.ip_address,
                        'status': 'running',
                        'logs': []
                    }
                    
                    deployer = None
                    try:
                        deployer = RemoteDeployer(
                            host=target.server.ip_address,
                            user=target.server.ssh_user,
                            port=target.server.ssh_port
                        )
                        deployer.connect()
                        
                        # Step 1: Prepare Directory
                        if target.prepare_dir:
                            self.stdout.write(f"Creating directory: {target.remote_path}")
                            mkdir_cmd = f"mkdir -p {target.remote_path}"
                            if target.server.os_type == 'windows':
                                mkdir_cmd = f"powershell -Command \"if (!(Test-Path '{target.remote_path}')) {{ New-Item -ItemType Directory -Force -Path '{target.remote_path}' }}\""
                            
                            status, out, err = deployer.execute_command(mkdir_cmd)
                            target_result['logs'].append(f"Mkdir (Code {status}): {out} {err}")

                        # Step 1.5: Special handling for Windows (PFX)
                        if target.server.os_type == 'windows':
                            ensure_pfx_exists(cert)

                        # Step 1.6: Root CA chain 번들 예방장치 — 매핑에 rootca가 있으면 최신 내용으로 보장
                        # (갱신으로 CA 체인이 바뀌었을 수 있으므로 force=True로 ca.cer 기준 최신화)
                        if any(m.file_type == 'rootca' for m in target.file_mappings.all()):
                            ensure_rootca_exists(cert, force=True)
                        # 매핑에 chain(중간 CA)이 있으면 최신 내용으로 보장 (Apache SSLCertificateChainFile)
                        if any(m.file_type == 'chain' for m in target.file_mappings.all()):
                            ensure_chain_exists(cert, force=True)
                        # 구형 기기용 cross-sign 변형 체인 (ZeroSSL): 매핑에 있으면 최신 생성
                        if any(m.file_type == 'chain_aaa' for m in target.file_mappings.all()):
                            ensure_chain_variant_exists(cert, 'aaa', force=True)
                        if any(m.file_type == 'chain_usertrust' for m in target.file_mappings.all()):
                            ensure_chain_variant_exists(cert, 'usertrust', force=True)

                        # Step 2: Transfer Files
                        if target.transfer_files:
                            for mapping in target.file_mappings.all():
                                source_filename = find_source_file(cert, mapping.file_type)
                                # Windows에서 fullchain 원본이 없으면 PFX로 폴백한다.
                                # 이때 실효 타입을 'pfx'로 바꿔, 대상 파일명과 default_dest 가 PFX 규칙({도메인}.pfx)을
                                # 따르도록 한다. (PowerShell 바인딩/리로드가 {도메인}.pfx 를 참조하므로 이름이 맞아야 함)
                                effective_type = mapping.file_type
                                if not source_filename:
                                    if mapping.file_type == 'fullchain' and target.server.os_type == 'windows':
                                        source_filename = find_source_file(cert, 'pfx')
                                        if source_filename:
                                            effective_type = 'pfx'
                                    elif mapping.file_type == 'rootca':
                                        # 예방장치로 한 번 더 생성 시도
                                        source_filename = ensure_rootca_exists(cert)
                                    elif mapping.file_type == 'chain':
                                        # 중간 CA 체인 예방장치 생성 시도
                                        source_filename = ensure_chain_exists(cert, force=True)
                                    elif mapping.file_type == 'chain_aaa':
                                        source_filename = ensure_chain_variant_exists(cert, 'aaa', force=True)
                                    elif mapping.file_type == 'chain_usertrust':
                                        source_filename = ensure_chain_variant_exists(cert, 'usertrust', force=True)

                                if not source_filename:
                                    target_result['logs'].append(f"Error: Source file for {mapping.file_type} not found.")
                                    continue
                                
                                local_path = os.path.join(cert.cert_path, source_filename)
                                
                                # 기본 배포 파일명 규칙 적용 ({도메인}.{타입}.확장자)
                                base_domain = cert.domain.replace('*.', '')
                                ext = os.path.splitext(source_filename)[1] or '.cer'
                                
                                if effective_type == 'fullchain':
                                    default_dest = f"{base_domain}_fullchain{ext}"
                                elif effective_type == 'key':
                                    default_dest = f"{base_domain}.key"
                                elif effective_type == 'cert':
                                    default_dest = f"{base_domain}{ext}"
                                elif effective_type == 'pfx':
                                    # PowerShell 바인딩/리로드가 {도메인}.pfx 를 참조하므로 대상명도 동일하게 맞춘다.
                                    default_dest = f"{base_domain}.pfx"
                                elif effective_type == 'rootca':
                                    default_dest = f"{base_domain}_RootCA.pem"
                                elif effective_type in ('chain', 'chain_aaa', 'chain_usertrust'):
                                    # 변형 체인도 기본 배포명은 표준 _chain.cer (서버 설정이 이를 가리킴)
                                    default_dest = f"{base_domain}_chain.cer"
                                else:
                                    default_dest = source_filename
                                    
                                dest_filename = mapping.custom_filename or default_dest

                                # 파일별 개별 경로(custom_path)가 지정되면 그 경로로, 아니면 타겟 공통 경로로 전송.
                                # custom_path 사용 시 원격 디렉토리를 자동 생성한다. (Linux & Windows)
                                dest_dir = (mapping.custom_path or '').strip() or target.remote_path
                                if mapping.custom_path and mapping.custom_path.strip():
                                    cp = mapping.custom_path.strip()
                                    if target.server.os_type == 'windows':
                                        mk = f"powershell -Command \"if (!(Test-Path '{cp}')) {{ New-Item -ItemType Directory -Force -Path '{cp}' }}\""
                                    else:
                                        mk = f"mkdir -p '{cp}'"
                                    m_status, m_out, m_err = deployer.execute_command(mk)
                                    target_result['logs'].append(f"Mkdir custom path '{cp}' (Code {m_status}): {m_out} {m_err}")

                                remote_path = os.path.join(dest_dir, dest_filename).replace('\\', '/')

                                self.stdout.write(f"Sending: {local_path} -> {remote_path}")
                                deployer.transfer_file(local_path, remote_path)
                                target_result['logs'].append(f"Transferred: {dest_filename} -> {dest_dir}")

                        # Step 3: Reload Service
                        if target.reload_service and target.reload_command:
                            self.stdout.write(f"Reloading: {target.reload_command}")
                            status, out, err = deployer.execute_command(target.reload_command)
                            target_result['logs'].append(f"Reload (Code {status}): {out} {err}")
                            if status != 0:
                                raise Exception(f"Reload failed: {err}")

                        # Step 3.5: Include All Bindings (Windows IIS) — EXEC와 별개로 실행
                        # IIS 작업이므로 웹서버 유형이 'iis'인 경우에만 실행 (안전장치)
                        if target.include_all_bindings and target.server.os_type == 'windows' and target.server.web_server_type == 'iis':
                            base_domain = cert.domain.replace('*.', '')
                            bind_cmd = build_all_bindings_command(target.remote_path, base_domain)
                            self.stdout.write("Applying certificate to empty-host 443 bindings (Include All Bindings)")
                            b_status, b_out, b_err = deployer.execute_command(bind_cmd)
                            target_result['logs'].append(f"AllBindings (Code {b_status}): {b_out} {b_err}")
                            if b_status != 0:
                                raise Exception(f"Include all bindings failed: {b_err}")

                        # Step 3.6: Cleanup expired certs (Windows IIS) — 우리 규칙으로 추가됐고 바인딩에 없는 만료건만 삭제
                        # IIS(WebAdministration) 작업이므로 서버 웹서버 유형이 'iis'이고 '스크립트 실행'이 켜져 있을 때만 수행.
                        # IIS가 없는 서버에 파일만 배포하는 경우 정리 명령이 실패하지 않도록 하기 위한 안전장치.
                        # 인증서 적용은 이미 끝났으므로, 정리 실패는 경고만 남기고 배포는 성공 처리한다.
                        if target.server.os_type == 'windows' and target.server.web_server_type == 'iis' and target.reload_service:
                            cleanup_cmd = build_cleanup_expired_command()
                            self.stdout.write("Cleaning up expired (unused) certificates imported by our rule")
                            c_status, c_out, c_err = deployer.execute_command(cleanup_cmd)
                            target_result['logs'].append(f"Cleanup (Code {c_status}): {c_out} {c_err}")
                            if c_status != 0:
                                self.stdout.write(self.style.WARNING(f"Cleanup warning: {c_err}"))

                        # Step 3.7: Restart Docker containers (Linux & Windows) — reload(EXEC)와 별개 독립 단계
                        # 선택된 컨테이너 이름들을 docker restart로 재시작한다. 컨테이너 이름에 셸 메타문자가
                        # 섞이지 않도록 영숫자/.-_ 만 허용해 필터링한다.
                        containers = [c for c in (target.restart_containers or [])
                                      if re.match(r'^[A-Za-z0-9][A-Za-z0-9_.-]*$', str(c))]
                        if containers:
                            restart_cmd = "docker restart " + " ".join(containers)
                            self.stdout.write(f"Restarting Docker containers: {', '.join(containers)}")
                            r_status, r_out, r_err = deployer.execute_command(restart_cmd)
                            target_result['logs'].append(f"Docker restart (Code {r_status}): {r_out} {r_err}")
                            if r_status != 0:
                                # 재시작 실패는 경고로 남기되 배포 자체는 성공 처리 (인증서 적용은 이미 끝남)
                                self.stdout.write(self.style.WARNING(f"Docker restart warning: {r_err}"))

                        target_result['status'] = 'success'
                        script_success_count += 1
                        self.stdout.write(self.style.SUCCESS(f"Success: {target.server.name}"))

                    except Exception as e:
                        script_fail_count += 1
                        overall_success = False
                        error_msg = f"Error: {str(e)}"
                        self.stdout.write(self.style.ERROR(error_msg))
                        target_result['status'] = 'failure'
                        target_result['logs'].append(error_msg)
                    finally:
                        if deployer:
                            deployer.close()
                        log_entry.details['targets'].append(target_result)
                        log_entry.save()

                    # --- Step 4: Discover & Save Sites ---
                    # Linux: SSL 설정 파일 파싱 / Windows: IIS https 바인딩 조회 (서버 관리 '사이트 테스트'와 동일)
                    do_discover = (
                        (target.server.os_type == 'linux' and target.server.ssl_config_path)
                        or target.server.os_type == 'windows'
                    )
                    if do_discover:
                        self.stdout.write(f"Discovering sites on {target.server.name} ({target.server.os_type})...")
                        d_deployer = None
                        try:
                            d_deployer = RemoteDeployer(host=target.server.ip_address, user=target.server.ssh_user, port=target.server.ssh_port)
                            d_deployer.connect()

                            discovered = []
                            if target.server.os_type == 'windows':
                                discovered = discover_iis_sites(d_deployer)
                            else:
                                c_status, c_out, c_err = d_deployer.execute_command(f"cat {target.server.ssl_config_path}")
                                if c_status == 0 and c_out:
                                    discovered = extract_domains_from_config(c_out, target.server.web_server_type)
                                else:
                                    self.stdout.write(self.style.WARNING(f"  Failed to read config file or file is empty. Status: {c_status}"))

                            if discovered:
                                # 1. 새로운 도메인 추가/갱신
                                for d_name, p_num in discovered:
                                    TargetServerSite.objects.update_or_create(
                                        server=target.server,
                                        domain=d_name,
                                        port=p_num
                                    )
                                # 2. 더 이상 발견되지 않는 도메인 삭제
                                discovered_domains = [d[0] for d in discovered]
                                stale_sites = TargetServerSite.objects.filter(server=target.server).exclude(domain__in=discovered_domains)
                                stale_count = stale_sites.count()
                                stale_sites.delete()
                                self.stdout.write(self.style.SUCCESS(f"  Synced: {len(discovered)} active domains found, {stale_count} stale domains removed."))
                            else:
                                self.stdout.write(self.style.WARNING(f"  No sites discovered on {target.server.name}."))
                        except Exception as de:
                            self.stdout.write(self.style.WARNING(f"  Site discovery failed: {de}"))
                        finally:
                            if d_deployer: d_deployer.close()
                    else:
                        self.stdout.write(f"Skipping site discovery (Linux SSL config path not set)")

                # Update overall script status
                if script_success_count == total_targets:
                    log_entry.status = 'success'
                elif script_success_count > 0:
                    log_entry.status = 'partial_success'
                else:
                    log_entry.status = 'failure'
                
                log_entry.log_output = f"Result: {script_success_count} success, {script_fail_count} failure out of {total_targets} targets."
                
                # --- Phase 2: Post-Deployment Verification ---
                if script_success_count > 0:
                    # 검증할 도메인 결정: 발견된 사이트 중 하나를 쓰거나, 기본 도메인 사용
                    test_domains = []
                    discovered_sites = TargetServerSite.objects.filter(server__in=[t.server for t in targets])
                    if discovered_sites.exists():
                        site_list = ', '.join(f"{s.domain}:{s.port}" for s in discovered_sites)
                        self.stdout.write(f"  Discovered sites: {site_list}")
                        # 발견된 사이트 중 배포된 인증서 도메인과 매칭되는 것들 추출
                        base_domain = cert.domain.replace('*.', '')
                        is_wildcard = cert.is_wildcard or cert.domain.startswith('*.')
                        for site in discovered_sites:
                            d_name = site.domain
                            is_match = False
                            if is_wildcard:
                                if d_name.endswith('.' + base_domain) or d_name == base_domain:
                                    is_match = True
                            elif d_name == cert.domain:
                                is_match = True
                            
                            if is_match:
                                test_domains.append((d_name, site.port))
                    
                    if not test_domains:
                        self.stdout.write(self.style.WARNING(
                            f"Skipping verification: no matching sites found in TargetServerSite for {cert.domain}. "
                            f"Run 'Site Test' on the server to discover active domains first."
                        ))
                        log_entry.details['verification'] = {'status': 'skipped', 'reason': 'No matching sites discovered'}
                        log_entry.finished_at = timezone.now()
                        log_entry.save()
                        script.last_executed = timezone.now()
                        script.save()
                        continue

                    self.stdout.write(f"Running post-deployment verification for {len(test_domains)} domains...")

                    # 배포 완료 후 cert 정보를 DB에서 재조회 + serial 없으면 파일에서 직접 파싱
                    cert.refresh_from_db()
                    if not cert.serial:
                        from core_cert.views import update_certificate_info
                        update_certificate_info(cert)
                        cert.save()
                        self.stdout.write(f"  [Info] Serial refreshed from cert file: {cert.serial}")

                    verification_results = []
                    for t_domain, t_port in test_domains[:3]: # 최대 3개까지만 검증
                        self.stdout.write(f"  Verifying {t_domain}:{t_port}...")
                        v_info = verify_site_certificate(t_domain, port=t_port)
                        if v_info:
                            match = False
                            # 1. Serial 비교 (가장 정확)
                            if cert.serial and v_info.get('serial'):
                                if cert.serial.upper() == v_info['serial'].upper():
                                    match = True
                            # 2. Serial 없으면 만료일 비교 (UTC 정규화 후)
                            if not match and cert.expiry_date and v_info.get('expiry_date'):
                                import datetime as _dt
                                c_expiry = cert.expiry_date.astimezone(_dt.timezone.utc)
                                v_expiry = v_info['expiry_date']
                                if hasattr(v_expiry, 'tzinfo') and v_expiry.tzinfo:
                                    v_expiry = v_expiry.astimezone(_dt.timezone.utc)
                                if c_expiry.strftime('%Y-%m-%d %H:%M') == v_expiry.strftime('%Y-%m-%d %H:%M'):
                                    match = True

                            res = {
                                'domain': t_domain,
                                'port': t_port,
                                'expiry_date': v_info['expiry_date'].isoformat() if v_info.get('expiry_date') else None,
                                'serial': v_info.get('serial'),
                                'match': match,
                                'status': 'verified'
                            }
                            verification_results.append(res)
                            if match:
                                self.stdout.write(self.style.SUCCESS(f"    Match success for {t_domain}"))
                            else:
                                msg = f"Verification mismatch for {t_domain} (Expected Serial: {cert.serial}, Found Serial: {v_info.get('serial')}, Expected Expiry: {cert.expiry_date}, Found Expiry: {v_info.get('expiry_date')})"
                                self.stdout.write(self.style.WARNING(f"    {msg}"))
                                logger.error(f"[Mismatch] {msg}")
                        else:
                            msg = f"Connection failed for {t_domain}:{t_port}"
                            self.stdout.write(self.style.ERROR(f"    {msg}"))
                            logger.error(f"[ConnectionFailed] {msg}")
                    
                    if verification_results:
                        log_entry.details['verification_list'] = verification_results
                        # 대표 결과 하나 설정 (레거시 호환)
                        log_entry.details['verification'] = verification_results[0]
                    else:
                        log_entry.details['verification'] = {'status': 'failed', 'error': 'No domains to verify'}
                
                log_entry.finished_at = timezone.now()
                log_entry.save()

                script.last_executed = timezone.now()
                script.save()

            if not overall_success:
                sys.exit(1)

        except Certificate.DoesNotExist:
            self.stdout.write(self.style.ERROR(f"Domain {domain_name} not found"))
            sys.exit(1)
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Fatal error: {str(e)}"))
            sys.exit(1)

import os
import subprocess
import re
import datetime
import logging
from datetime import datetime as dt_class

from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic import ListView, CreateView, UpdateView
from django.urls import reverse_lazy
from django.utils import timezone
from django.contrib import messages
from django.forms import inlineformset_factory
from django.http import JsonResponse
from django.utils.translation import gettext as _

from .models import Certificate, DeployScript, DeploymentLog, TargetServer, GlobalSetting, DeploymentTarget, FileMapping, TargetServerSite
from .forms import CertificateForm, DeployScriptForm, DeploymentTargetForm, FileMappingForm, TargetServerForm
from . import ssh_manager
from .deployer import RemoteDeployer
from .utils import verify_site_certificate

logger = logging.getLogger('core_cert')

# --- Global Settings ---

def save_global_settings(request):
    if request.method == 'POST':
        key = request.POST.get('key')
        value = request.POST.get('value')
        # value가 빈 문자열이어도 저장을 허용한다.
        # 예) ACMEDNS_BASE_URL을 비워서 저장하면 acme.sh 기본 동작으로 되돌린다.
        if key:
            GlobalSetting.set_value(key, (value or '').strip())
            messages.success(request, _("Settings ({key}) saved.").format(key=key))
        return redirect(request.META.get('HTTP_REFERER', 'core_cert:settings'))
    return redirect('core_cert:settings')

def global_settings_view(request):
    return render(request, 'core_cert/settings.html')

# --- Certificate Management ---

def update_certificate_info(instance, sync_wildcard=False):
    """인증서 파일에서 만료일과 상태를 자동으로 감지하여 업데이트합니다."""
    if not instance.cert_path: return
    full_path = instance.cert_path
    # leaf 인증서(cert)를 우선 사용한다. fullchain은 여러 인증서를 담고 있어
    # openssl x509 -in 이 첫 번째 인증서만 읽는데, 그게 leaf가 아니라 CA/Root일 경우
    # 만료일·갱신일이 엉뚱하게 루트 인증서 기준으로 들어가기 때문이다.
    cert_file_name = instance.get_source_file('cert') or instance.get_source_file('fullchain')
    if not cert_file_name: return
    cert_file = os.path.join(full_path, cert_file_name)

    if os.path.exists(cert_file):
        try:
            output = subprocess.check_output(['openssl', 'x509', '-text', '-noout', '-in', cert_file], stderr=subprocess.STDOUT, universal_newlines=True)
            expiry_date = None
            for line in output.split('\n'):
                if 'Not After :' in line:
                    date_str = line.split(':', 1)[1].strip()
                    try: expiry_date = timezone.make_aware(dt_class.strptime(date_str, '%b %d %H:%M:%S %Y %Z'))
                    except: expiry_date = timezone.make_aware(dt_class.strptime(date_str, '%b %d %H:%M:%S %Y'))
                    break
            if expiry_date:
                instance.expiry_date = expiry_date
                instance.status = 'expired' if expiry_date < timezone.now() else 'valid'
            # Serial Number can be on the same line or the next line (ZeroSSL vs LE format)
            serial_match = re.search(r"Serial Number:\s*\n?\s*([0-9a-fA-F:]+)", output)
            if serial_match: instance.serial = serial_match.group(1).replace(':', '').upper()
            else:
                serial_match = re.search(r"serial=([0-9a-fA-F]+)", output)
                if serial_match: instance.serial = serial_match.group(1).upper()
            instance.is_wildcard = '*.' in output if sync_wildcard else (instance.is_wildcard or '*.' in output)
            domains = set()
            san_match = re.search(r"X509v3 Subject Alternative Name:.*?(\n\s+DNS:.*)+", output, re.DOTALL)
            if san_match: domains.update(re.findall(r"DNS:([^\s,]+)", san_match.group(0)))
            cn_match = re.search(r"Subject:.*?CN\s*=\s*([^\s,/]+)", output)
            if cn_match: domains.add(cn_match.group(1))
            instance.allowed_domains = ", ".join(sorted(list(domains)))
        except Exception as e: print(f"Error parsing cert {instance.domain}: {e}"); instance.status = 'unknown'

def find_source_file(cert, file_type): return cert.get_source_file(file_type)

def build_cert_source_file_map(form):
    """배포 스크립트 폼의 인증서 드롭다운에 있는 각 인증서에 대해,
    file_type별 '실제 원본 파일명'을 미리 계산해 {cert_id: {file_type: filename}} 형태로 반환한다.
    수동/자동 인증서마다 파일명이 다를 수 있어, 미리보기(시뮬레이션)가 실제 SCP 동작과
    일치하도록 deploy_domain 과 동일한 탐색 결과(get_source_file)를 프론트엔드에 내려준다.
    실제 파일이 없으면 acme.sh 기본 명명 규칙을 폴백으로 채운다.
    반환값은 템플릿에서 바로 쓸 수 있는 JSON 문자열이다."""
    import json
    result = {}
    try:
        qs = form.fields['certificate'].queryset
    except Exception:
        return json.dumps(result)
    file_types = ['fullchain', 'key', 'cert', 'pfx', 'rootca', 'chain', 'chain_aaa', 'chain_usertrust']
    for cert in qs:
        base = cert.domain.replace('*.', '')
        fallback = {
            'fullchain': f"{base}_fullchain.cer", 'key': f"{base}.key", 'cert': f"{base}.cer",
            'pfx': f"{base}.pfx", 'rootca': f"{base}_RootCA.pem", 'chain': f"{base}_chain.cer",
            'chain_aaa': f"{base}_chain_AAA.cer", 'chain_usertrust': f"{base}_chain_USERTRUST.cer",
        }
        entry = {}
        for ft in file_types:
            try:
                actual = cert.get_source_file(ft)
            except Exception:
                actual = None
            entry[ft] = actual or fallback[ft]
        result[str(cert.id)] = entry
    import json
    return json.dumps(result)

def ensure_rootca_exists(cert, force=False):
    """인증서 폴더 안에 '<도메인>_RootCA.pem' (leaf 제외 CA 체인 전체)을 생성한다.
    우선순위: acme.sh의 ca.cer 사용 → 없으면 fullchain에서 leaf(첫 인증서) 제외해 생성.
    force=False면 이미 존재할 때 그대로 두고, force=True면 항상 최신 내용으로 덮어쓴다
    (갱신으로 CA 체인이 바뀌는 경우 대비). 성공 시 파일명을 반환한다."""
    if not cert.cert_path or not os.path.exists(cert.cert_path):
        return None
    base_domain = cert.domain.replace('*.', '')
    rootca_name = f"{base_domain}_RootCA.pem"
    rootca_path = os.path.join(cert.cert_path, rootca_name)
    if os.path.exists(rootca_path) and not force:
        return rootca_name

    # 1순위: acme.sh가 만든 ca.cer (leaf 제외 CA 체인)
    ca_path = os.path.join(cert.cert_path, 'ca.cer')
    try:
        if os.path.exists(ca_path) and os.path.getsize(ca_path) > 0:
            with open(ca_path, 'r') as src, open(rootca_path, 'w') as dst:
                dst.write(src.read())
            return rootca_name

        # 2순위(수동 등): 폴더 내 모든 CA 인증서(루트 포함)를 중복 없이 모아 전체 CA 번들 생성.
        # _RootCA.pem 은 "leaf 제외 CA 체인 전체"가 목적이므로 self-signed 루트도 포함한다.
        leaf_name = cert.get_source_file('cert')
        leaf_pem = ''
        if leaf_name:
            with open(os.path.join(cert.cert_path, leaf_name), 'r', errors='ignore') as f:
                leaf_pem = f.read().strip()

        ca_blocks = []
        seen = set()
        for fname in sorted(os.listdir(cert.cert_path)):
            fp = os.path.join(cert.cert_path, fname)
            if not os.path.isfile(fp) or fname == rootca_name or fname.lower().endswith(('.pfx', '.key', '.zip', '.pdf', '.jks', '.p7b', '.srl')):
                continue
            for b in _split_pem_certs(open(fp, 'r', errors='ignore').read()):
                info = _analyze_cert_block(b)
                if not info or not (info['is_ca'] or info['self_signed']):
                    continue  # leaf는 제외
                key = (info['subject'], info['issuer'])
                if key in seen:
                    continue
                seen.add(key)
                ca_blocks.append(b)

        if ca_blocks:
            with open(rootca_path, 'w') as out:
                out.write(''.join(ca_blocks))
            return rootca_name

        # 3순위: fullchain에서 leaf(첫 인증서) 제외한 나머지
        fc_name = cert.get_source_file('fullchain')
        if fc_name:
            with open(os.path.join(cert.cert_path, fc_name), 'r') as f:
                content = f.read()
            certs = _split_pem_certs(content)
            if len(certs) > 1:
                with open(rootca_path, 'w') as out:
                    out.write(''.join(certs[1:]))
                return rootca_name
    except Exception as e:
        print(f"RootCA generation failed: {e}")
    return None

def ensure_chain_exists(cert, force=False):
    """Apache SSLCertificateChainFile용 '<도메인>_chain.cer'를 생성한다.
    = leaf 제외 + self-signed 루트 제외 = 중간 CA만 (acme.sh ca.cer 과 동일한 성격, 원본 그대로).
    우선순위: fullchain에서 leaf 제외 후 루트 제외 → 없으면 ca.cer(루트 제외) → 없으면 폴더 내 중간 CA 수집.
    성공 시 파일명 반환. (구형 기기용 cross-sign 변형은 ensure_chain_variant_exists 참고)"""
    if not cert.cert_path or not os.path.exists(cert.cert_path):
        return None
    base_domain = cert.domain.replace('*.', '')
    chain_name = f"{base_domain}_chain.cer"
    chain_path = os.path.join(cert.cert_path, chain_name)
    if os.path.exists(chain_path) and not force:
        return chain_name

    def _intermediates_from(blocks):
        out = []
        seen = set()
        for b in blocks:
            info = _analyze_cert_block(b)
            if not info:
                continue
            # 중간 CA만: CA이면서 self-signed(루트) 아님, leaf 아님
            if info['is_ca'] and not info['self_signed']:
                key = (info['subject'], info['issuer'])
                if key not in seen:
                    seen.add(key)
                    out.append(b)
        return out

    try:
        # 1순위: fullchain에서 중간 CA 추출
        fc_name = cert.get_source_file('fullchain')
        inter = []
        if fc_name:
            with open(os.path.join(cert.cert_path, fc_name), 'r', errors='ignore') as f:
                inter = _intermediates_from(_split_pem_certs(f.read()))

        # 2순위: acme.sh ca.cer (보통 중간 CA 묶음)
        if not inter:
            ca_path = os.path.join(cert.cert_path, 'ca.cer')
            if os.path.exists(ca_path) and os.path.getsize(ca_path) > 0:
                with open(ca_path, 'r', errors='ignore') as f:
                    inter = _intermediates_from(_split_pem_certs(f.read()))

        # 3순위: 폴더 내 모든 인증서 파일에서 중간 CA 수집
        if not inter:
            collected = []
            for fname in sorted(os.listdir(cert.cert_path)):
                fp = os.path.join(cert.cert_path, fname)
                if not os.path.isfile(fp) or fname == chain_name or fname.lower().endswith(('.pfx', '.key', '.zip', '.pdf', '.jks', '.p7b', '.srl')):
                    continue
                with open(fp, 'r', errors='ignore') as f:
                    collected.extend(_split_pem_certs(f.read()))
            inter = _intermediates_from(collected)

        if inter:
            with open(chain_path, 'w') as out:
                out.write(''.join(inter))
            return chain_name
    except Exception as e:
        print(f"Chain generation failed: {e}")
    return None


def ensure_chain_variant_exists(cert, variant, force=True):
    """구형 기기 호환용 cross-sign 변형 체인 '<도메인>_chain_<VARIANT>.cer'를 생성한다.
    variant: 'aaa' 또는 'usertrust'. 기본 _chain.cer(중간 CA만)를 만든 뒤, 체인 최상위
    중간 CA를 선택한 variant의 cross-sign 인증서로 교체한다(예: Sectigo R46 → issuer=AAA).
    해당 variant의 교체 대상이 번들에 없거나 체인이 이미 그 issuer로 끝나면 변형이 불필요하므로
    None을 반환한다. 성공 시 생성된 파일명을 반환한다."""
    if not cert.cert_path or not os.path.exists(cert.cert_path):
        return None
    variant = (variant or '').lower()
    if variant not in _CROSS_VARIANTS:
        return None
    base_domain = cert.domain.replace('*.', '')
    out_name = f"{base_domain}_chain_{variant.upper()}.cer"
    out_path = os.path.join(cert.cert_path, out_name)
    if os.path.exists(out_path) and not force:
        return out_name

    # 기본 중간 CA 체인을 먼저 보장한 뒤 그 내용을 읽어 변형한다.
    base_chain_name = ensure_chain_exists(cert, force=force)
    if not base_chain_name:
        return None
    try:
        with open(os.path.join(cert.cert_path, base_chain_name), 'r', errors='ignore') as f:
            inter = _split_pem_certs(f.read())
        if not inter:
            return None

        variants = _load_cross_cert_variants()
        repl_map = variants.get(variant, {})
        if not repl_map:
            return None  # 해당 variant 번들 없음

        top_info = _analyze_cert_block(inter[-1])
        if not top_info or top_info['self_signed']:
            return None
        repl = repl_map.get(top_info['subject'])
        if not repl:
            return None  # 이 인증서(예: LE)는 해당 variant 교체 대상 아님
        repl_info = _analyze_cert_block(repl)
        # 이미 같은 issuer로 끝나더라도(예: ZeroSSL 기본=USERTrust) 사용자가 명시 선택할 수 있도록
        # 변형 파일을 생성한다. 결과적으로 기본 _chain.cer와 동일 내용이 될 수 있다.
        inter[-1] = repl
        with open(out_path, 'w') as out:
            out.write(''.join(inter))
        print(f"Chain variant '{variant}': {out_name} (top issuer -> "
              f"{repl_info['issuer'] if repl_info else '?'}) for {base_domain}")
        return out_name
    except Exception as e:
        print(f"Chain variant generation failed: {e}")
    return None


def ensure_pfx_exists(cert):
    if not cert.cert_path or not os.path.exists(cert.cert_path): return False
    base_domain = cert.domain.replace('*.', '')
    pfx_path = os.path.join(cert.cert_path, f"{base_domain}.pfx")
    key, crt, fc = cert.get_source_file('key'), cert.get_source_file('cert'), cert.get_source_file('fullchain')
    if not all([key, crt, fc]): return False
    try:
        cmd = ['openssl', 'pkcs12', '-export', '-out', pfx_path, '-inkey', os.path.join(cert.cert_path, key), '-in', os.path.join(cert.cert_path, crt), '-certfile', os.path.join(cert.cert_path, fc), '-passout', 'pass:password', '-legacy', '-descert']
        subprocess.run(cmd, check=True, capture_output=True); return True
    except Exception as e: print(f"PFX failed: {e}"); return False

OLD_BACKUP_DIRNAME = '_old'
OLD_BACKUP_INFO = '.backup_info'


def get_old_backup_info(cert):
    """직전 인증서 백업(_old 폴더) 정보를 반환한다.
    반환: {'exists': bool, 'date': '<문자열>' or None, 'files': [파일명...]}"""
    info = {'exists': False, 'date': None, 'files': []}
    if not cert.cert_path:
        return info
    old_dir = os.path.join(cert.cert_path, OLD_BACKUP_DIRNAME)
    if not os.path.isdir(old_dir):
        return info
    # 실제 백업 파일 목록 (백업 정보 파일 제외). 파일이 하나도 없으면 백업 없음으로 취급.
    try:
        files = sorted(f for f in os.listdir(old_dir)
                       if f != OLD_BACKUP_INFO and os.path.isfile(os.path.join(old_dir, f)))
    except Exception:
        files = []
    if not files:
        return info
    info['exists'] = True
    info['files'] = files
    # 백업 시각 읽기 (없으면 폴더 mtime으로 폴백)
    info_path = os.path.join(old_dir, OLD_BACKUP_INFO)
    if os.path.exists(info_path):
        try:
            with open(info_path) as f:
                info['date'] = f.read().strip()
        except Exception:
            pass
    if not info['date']:
        try:
            from django.utils import timezone as _tz
            import datetime as _dt
            ts = os.path.getmtime(old_dir)
            info['date'] = _tz.localtime(_dt.datetime.fromtimestamp(ts, _dt.timezone.utc)).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
    return info


def backup_manual_cert_files(cert):
    """cert_path 내 현재 파일들을 _old 폴더로 백업한다 (직전 1개만 유지).
    기존 _old 가 있으면 비우고 새로 채운다. 백업 시각을 _old/.backup_info 에 기록한다.
    반환: 백업한 파일 수 (백업할 게 없으면 0)."""
    import shutil
    from django.utils import timezone as _tz
    dest = cert.cert_path
    if not dest or not os.path.isdir(dest):
        return 0
    old_dir = os.path.join(dest, OLD_BACKUP_DIRNAME)
    # 백업 대상: _old 자신을 제외한 cert_path 직속 파일들
    entries = [e for e in os.listdir(dest) if e != OLD_BACKUP_DIRNAME]
    files = [e for e in entries if os.path.isfile(os.path.join(dest, e))]
    if not files:
        return 0
    # 기존 _old 폴더는 통째로 제거 후 재생성 (직전 1개만 유지)
    if os.path.exists(old_dir):
        shutil.rmtree(old_dir, ignore_errors=True)
    os.makedirs(old_dir, exist_ok=True)
    count = 0
    for fname in files:
        try:
            shutil.move(os.path.join(dest, fname), os.path.join(old_dir, fname))
            count += 1
        except Exception:
            pass
    # 백업 시각 기록
    try:
        with open(os.path.join(old_dir, OLD_BACKUP_INFO), 'w') as f:
            f.write(_tz.localtime(_tz.now()).strftime('%Y-%m-%d %H:%M:%S'))
    except Exception:
        pass
    return count


def restore_manual_cert_files(cert):
    """_old 폴더의 직전 인증서를 cert_path 로 복구한다.
    현재 파일들은 다시 _old 로 옮겨 스왑한다(복구 후에도 직전 상태로 되돌릴 수 있게).
    반환: (성공 여부, 메시지)"""
    import shutil, tempfile
    from django.utils import timezone as _tz
    dest = cert.cert_path
    if not dest or not os.path.isdir(dest):
        return False, "cert_path is not set."
    old_dir = os.path.join(dest, OLD_BACKUP_DIRNAME)
    if not os.path.isdir(old_dir):
        return False, "no_backup"
    old_files = [f for f in os.listdir(old_dir) if f != OLD_BACKUP_INFO and os.path.isfile(os.path.join(old_dir, f))]
    if not old_files:
        return False, "no_backup"
    # 1) 현재 파일들을 임시 폴더로 잠시 대피 (_old 제외)
    tmp_dir = tempfile.mkdtemp(prefix='cert_swap_', dir=dest)
    try:
        for e in os.listdir(dest):
            if e in (OLD_BACKUP_DIRNAME, os.path.basename(tmp_dir)):
                continue
            p = os.path.join(dest, e)
            if os.path.isfile(p):
                shutil.move(p, os.path.join(tmp_dir, e))
        # 2) _old 의 파일들을 cert_path 로 복구
        for fname in old_files:
            shutil.move(os.path.join(old_dir, fname), os.path.join(dest, fname))
        # 3) _old 를 비우고, 대피해 둔 (직전까지 현재였던) 파일들을 _old 로 이동 (스왑)
        shutil.rmtree(old_dir, ignore_errors=True)
        os.makedirs(old_dir, exist_ok=True)
        for e in os.listdir(tmp_dir):
            shutil.move(os.path.join(tmp_dir, e), os.path.join(old_dir, e))
        with open(os.path.join(old_dir, OLD_BACKUP_INFO), 'w') as f:
            f.write(_tz.localtime(_tz.now()).strftime('%Y-%m-%d %H:%M:%S'))
        return True, "restored"
    except Exception as e:
        return False, str(e)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def extract_manual_zip(cert, uploaded_zip):
    """업로드된 ZIP을 인증서의 cert_path(=/app/acme.sh/manual/<도메인>) 안에 압축 해제한다.
    추출 전, 기존 파일들을 _old 폴더로 백업한다 (직전 1개만 유지).
    경로 탈출(zip slip) 방지를 위해 멤버 경로를 정규화하여 검증한다.
    반환: (성공 여부, 메시지)"""
    import zipfile, shutil, tempfile
    dest = cert.cert_path
    if not dest:
        return False, "cert_path is not set."
    os.makedirs(dest, exist_ok=True)
    # 새 ZIP 추출 전, 현재 파일을 _old 로 백업 (직전 1개만)
    backup_manual_cert_files(cert)

    # 업로드 파일을 임시 파일로 저장
    tmp_fd, tmp_path = tempfile.mkstemp(suffix='.zip')
    try:
        with os.fdopen(tmp_fd, 'wb') as tmp:
            for chunk in uploaded_zip.chunks():
                tmp.write(chunk)

        if not zipfile.is_zipfile(tmp_path):
            return False, "Uploaded file is not a valid ZIP archive."

        with zipfile.ZipFile(tmp_path) as zf:
            dest_real = os.path.realpath(dest)
            for member in zf.namelist():
                if member.endswith('/'):
                    continue
                # ZIP 내부 경로에서 파일명만 추출 (디렉토리 구조 평탄화)
                fname = os.path.basename(member)
                if not fname:
                    continue
                target = os.path.realpath(os.path.join(dest, fname))
                if not target.startswith(dest_real + os.sep) and target != dest_real:
                    continue  # zip slip 방지
                with zf.open(member) as src, open(target, 'wb') as out:
                    shutil.copyfileobj(src, out)
        return True, "Extracted."
    except Exception as e:
        return False, str(e)
    finally:
        try: os.remove(tmp_path)
        except: pass


def _split_pem_certs(content):
    """PEM 문자열에서 인증서 블록(-----BEGIN/END CERTIFICATE-----)들을 리스트로 분리한다."""
    marker = '-----BEGIN CERTIFICATE-----'
    end = '-----END CERTIFICATE-----'
    blocks = []
    idx = 0
    while True:
        s = content.find(marker, idx)
        if s == -1:
            break
        e = content.find(end, s)
        if e == -1:
            break
        blocks.append(content[s:e + len(end)] + '\n')
        idx = e + len(end)
    return blocks


def _analyze_cert_block(pem):
    """단일 인증서 PEM 블록을 openssl로 분석한다.
    반환: {'subject':..., 'issuer':..., 'is_ca':bool, 'self_signed':bool, 'sans':[...]}
    실패 시 None."""
    try:
        out = subprocess.check_output(
            ['openssl', 'x509', '-noout', '-subject', '-issuer', '-ext', 'basicConstraints,subjectAltName'],
            input=pem, stderr=subprocess.STDOUT, universal_newlines=True)
    except Exception:
        try:
            out = subprocess.check_output(
                ['openssl', 'x509', '-noout', '-subject', '-issuer', '-text'],
                input=pem, stderr=subprocess.STDOUT, universal_newlines=True)
        except Exception:
            return None
    subject = issuer = ''
    for line in out.split('\n'):
        if line.startswith('subject='):
            subject = line[len('subject='):].strip()
        elif line.startswith('issuer='):
            issuer = line[len('issuer='):].strip()
    is_ca = 'CA:TRUE' in out
    sans = re.findall(r"DNS:([^\s,]+)", out)
    return {
        'subject': subject,
        'issuer': issuer,
        'is_ca': is_ca,
        'self_signed': bool(subject) and subject == issuer,
        'sans': sans,
    }


# 구형 기기(예: Windows 7 SP1) 호환용 cross-sign 대체 인증서 번들.
# ZeroSSL/Sectigo는 fullchain을 새 루트(Sectigo R46/E46)의 cross-sign 버전으로 끝내는데,
# 그 상위 루트(USERTrust)를 모르는 구형 기기는 체인을 완성하지 못한다. 같은 중간 CA를
# 더 오래된 루트가 cross-sign한 변형으로 "교체"하면 구형 기기까지 체인이 연결된다.
# 기본 _chain.cer는 acme.sh 원본(교체 없음)이고, 사용자는 배포 시 _chain_AAA / _chain_USERTrust
# 변형 파일을 선택해 보낼 수 있다 (whatsmychaincert.com 권장 = AAA).
_CROSS_CERT_DIR = os.path.join(os.path.dirname(__file__), 'cross_certs')

# 변형 식별자 → 해당 variant의 cross-sign 발급자(issuer CN 일부) 매칭 키워드
_CROSS_VARIANTS = {
    'aaa': 'AAA Certificate Services',
    'usertrust': 'USERTrust',
}


def _load_cross_cert_variants():
    """cross_certs 폴더의 PEM들을 읽어 {variant: {subject: pem_block}} 매핑으로 반환한다.
    variant는 issuer CN으로 판별('aaa' 또는 'usertrust'). 같은 subject의 중간 CA를
    선택한 variant의 cross-sign 인증서로 교체하는 데 사용한다."""
    variants = {k: {} for k in _CROSS_VARIANTS}
    if not os.path.isdir(_CROSS_CERT_DIR):
        return variants
    for fname in sorted(os.listdir(_CROSS_CERT_DIR)):
        fp = os.path.join(_CROSS_CERT_DIR, fname)
        if not os.path.isfile(fp) or not fname.lower().endswith(('.pem', '.cer', '.crt')):
            continue
        try:
            with open(fp, 'r', errors='ignore') as f:
                for b in _split_pem_certs(f.read()):
                    info = _analyze_cert_block(b)
                    if not info or not info['subject']:
                        continue
                    for vkey, issuer_kw in _CROSS_VARIANTS.items():
                        if issuer_kw in info['issuer']:
                            variants[vkey][info['subject']] = b
        except Exception:
            continue
    return variants


def _classify_pem_file(filepath, base_domain=''):
    """PEM 파일을 인증서 내용 기반으로 정밀 분류한다.
    반환: 'key' | 'leaf' | 'fullchain' | 'ca' | None
      - leaf      : 단일 leaf(엔드엔티티) 인증서
      - fullchain : leaf + 체인(CA) 인증서들
      - ca        : leaf 없이 CA/Root 인증서들만 (RootCA 번들)
    """
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
    except Exception:
        return None
    if 'PRIVATE KEY' in content:
        return 'key'
    blocks = _split_pem_certs(content)
    if not blocks:
        return None

    def is_leaf(info):
        if info is None:
            return False
        # leaf: CA가 아니거나, SAN에 도메인이 포함된 엔드엔티티(self-signed 아님)
        if info['self_signed']:
            return False
        if not info['is_ca']:
            return True
        if base_domain and any(base_domain in s or s.replace('*.', '') == base_domain for s in info['sans']):
            return True
        return False

    first = _analyze_cert_block(blocks[0])
    first_is_leaf = is_leaf(first)

    if len(blocks) == 1:
        return 'leaf' if first_is_leaf else 'ca'
    # 인증서 여러 개
    if first_is_leaf:
        return 'fullchain'
    # 첫 블록이 leaf가 아니면 leaf가 어디 섞였는지 확인
    if any(is_leaf(_analyze_cert_block(b)) for b in blocks):
        return 'fullchain'  # 순서만 뒤집힌 fullchain
    return 'ca'  # leaf 없는 CA 번들


def _read_pem_kind(filepath, base_domain=''):
    """하위호환 래퍼. 'key' | 'cert' | 'fullchain' | None 로 매핑."""
    k = _classify_pem_file(filepath, base_domain)
    if k == 'leaf':
        return 'cert'
    if k in ('fullchain', 'key', 'ca'):
        return k if k != 'ca' else None
    return k


def _file_has_intermediate(filepath):
    """파일 안에 중간 CA(CA이면서 self-signed 아님)가 들어있는지, 루트만 있는지 분석.
    반환: (중간CA개수, 루트개수)"""
    inter = root = 0
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for b in _split_pem_certs(f.read()):
                info = _analyze_cert_block(b)
                if not info:
                    continue
                if info['self_signed']:
                    root += 1
                elif info['is_ca']:
                    inter += 1
    except Exception:
        pass
    return inter, root


def detect_manual_files(cert):
    """수동 인증서 폴더 내 파일들을 내용 기반으로 분석하여 key/cert/fullchain/chain 추정값과
    전체 파일 목록(각 파일의 분류 포함)을 반환한다.
    반환: {'files': [{'name':.., 'kind':..}...], 'guess': {'key':.., 'cert':.., 'fullchain':.., 'chain':..}}
      kind: 'key' | 'leaf' | 'fullchain' | 'ca' | 'pfx' | 'other'"""
    result = {'files': [], 'guess': {'key': '', 'cert': '', 'fullchain': '', 'chain': ''}}
    if not cert.cert_path or not os.path.exists(cert.cert_path):
        return result
    base_domain = cert.domain.replace('*.', '') if cert.domain else ''
    chain_best_score = -1  # chain 후보 점수: 중간 CA만 있을수록(루트 없을수록) 높게
    for fname in sorted(os.listdir(cert.cert_path)):
        fpath = os.path.join(cert.cert_path, fname)
        if not os.path.isfile(fpath):
            continue
        low = fname.lower()
        if low.endswith('.pfx'):
            result['files'].append({'name': fname, 'kind': 'pfx'})
            continue
        kind = _classify_pem_file(fpath, base_domain) or 'other'
        result['files'].append({'name': fname, 'kind': kind})

        if kind == 'fullchain':
            if not result['guess']['fullchain'] or 'fullchain' in low or 'chain' in low:
                result['guess']['fullchain'] = fname
        elif kind == 'leaf':
            if not result['guess']['cert'] or base_domain in fname:
                result['guess']['cert'] = fname
        elif kind == 'key':
            if not result['guess']['key'] or 'key' in low or 'priv' in low:
                result['guess']['key'] = fname

        # chain(중간 CA) 추정: 'ca' 또는 'fullchain' 파일 중 중간 CA를 포함한 것.
        # 중간 CA만 있고 루트가 없을수록, 그리고 파일명에 chain 힌트가 있을수록 우선.
        if kind in ('ca', 'fullchain'):
            inter, root = _file_has_intermediate(fpath)
            if inter > 0:
                score = inter * 10 - root * 5
                if 'chain' in low:
                    score += 100
                # leaf가 섞인 fullchain보다 순수 CA 번들을 선호
                if kind == 'ca':
                    score += 20
                if score > chain_best_score:
                    chain_best_score = score
                    result['guess']['chain'] = fname
    return result


def _extract_leaf_block(path):
    """주어진 PEM 파일(보통 fullchain)에서 leaf(엔드엔티티) 인증서 블록을 내용 기반으로 골라 반환한다.
    leaf를 못 찾으면 첫 블록을 반환. 인증서가 없으면 None."""
    try:
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
    except Exception:
        return None
    blocks = _split_pem_certs(content)
    if not blocks:
        return None
    for b in blocks:
        info = _analyze_cert_block(b)
        if info and not info['self_signed'] and not info['is_ca']:
            return b
    return blocks[0]


def _build_standard_chain(leaf_pem, ca_pem_blocks):
    """acme.sh 표준에 맞는 중간 CA 체인을 구성한다.
    - self-signed 루트는 제외 (acme.sh의 fullchain 관례)
    - leaf의 issuer 부터 시작해 issuer→subject 로 순서대로 연결
    인자: leaf_pem(문자열), ca_pem_blocks(중복 가능한 PEM 블록 리스트)
    반환: 순서대로 정렬된 중간 CA PEM 블록 리스트 (루트 제외)"""
    # subject -> (pem, info) 매핑 (self-signed 루트는 후보에서 제외)
    by_subject = {}
    for b in ca_pem_blocks:
        info = _analyze_cert_block(b)
        if not info or not info['subject']:
            continue
        if info['self_signed']:
            continue  # 루트 제외
        # 동일 subject 중복 시 첫 번째만 유지
        if info['subject'] not in by_subject:
            by_subject[info['subject']] = (b, info)

    leaf_info = _analyze_cert_block(leaf_pem)
    chain = []
    used = set()
    next_issuer = leaf_info['issuer'] if leaf_info else None
    # issuer 체인을 따라가며 중간 CA를 순서대로 연결
    while next_issuer and next_issuer in by_subject and next_issuer not in used:
        b, info = by_subject[next_issuer]
        chain.append(b)
        used.add(next_issuer)
        next_issuer = info['issuer']
    # 체인 연결이 안 된(issuer로 이어지지 않는) 나머지 중간 CA도 누락 없이 뒤에 추가
    for subj, (b, info) in by_subject.items():
        if subj not in used:
            chain.append(b)
            used.add(subj)
    return chain


def finalize_manual_cert(cert, key_file, cert_file, fullchain_file, chain_file=None):
    """수동 인증서: 사용자가 지정한 파일들을 표준 파일명으로 정리하고 PFX를 생성한다.
    표준 파일명: <base>.key, <base>.cer, <base>_fullchain.cer, <base>_chain.cer
    - cert(leaf) 미지정 시: fullchain에서 leaf 블록을 내용 기반으로 추출
    - fullchain 미지정 시: leaf + 중간 CA(루트 제외)를 합쳐 자동 생성
    - chain(중간 CA) 지정 시: 그 파일의 중간 CA만 표준화해 <base>_chain.cer 생성
      미지정 시: fullchain 등에서 중간 CA를 자동 추출(ensure_chain_exists)
    반환: (성공 여부, 메시지)"""
    import shutil
    if not cert.cert_path or not os.path.exists(cert.cert_path):
        return False, "Certificate path not found."
    base = cert.domain.replace('*.', '')
    path = cert.cert_path

    def _copy_to(src_name, std_name):
        if not src_name:
            return False
        src = os.path.join(path, src_name)
        dst = os.path.join(path, std_name)
        if not os.path.exists(src):
            return False
        if os.path.realpath(src) != os.path.realpath(dst):
            shutil.copyfile(src, dst)
        return True

    std_key = f"{base}.key"
    std_cert = f"{base}.cer"
    std_fc = f"{base}_fullchain.cer"

    has_key = _copy_to(key_file, std_key)
    # fullchain 원본은 일단 그대로 복사하고, leaf 확정 후 표준화(루트 제외)한다.
    has_fc_src = _copy_to(fullchain_file, std_fc)

    # 1) leaf(cert) 확정
    if cert_file:
        has_cert = _copy_to(cert_file, std_cert)
    elif has_fc_src:
        # fullchain에서 leaf 블록을 내용 기반으로 추출
        leaf = _extract_leaf_block(os.path.join(path, std_fc))
        if leaf:
            with open(os.path.join(path, std_cert), 'w') as out:
                out.write(leaf)
            has_cert = True
        else:
            has_cert = False
    else:
        has_cert = False

    # 2) acme.sh 표준 fullchain 생성: leaf + 중간 CA(순서 정렬, self-signed 루트 제외)
    #    - 지정된 fullchain이 있으면 그 안의 CA들을 후보로 사용 (루트가 섞여 있어도 표준화하며 제거)
    #    - 없으면 폴더 내 모든 CA/체인 파일에서 중간 CA를 수집
    has_fc = False
    if has_cert:
        try:
            with open(os.path.join(path, std_cert), 'r', errors='ignore') as f:
                leaf_pem = f.read()
            ca_candidates = []

            def _collect_from(fp):
                with open(fp, 'r', errors='ignore') as cf:
                    for b in _split_pem_certs(cf.read()):
                        info = _analyze_cert_block(b)
                        # leaf(엔드엔티티)는 제외하고 CA 후보만 모은다
                        if info and (info['is_ca'] or info['self_signed']):
                            ca_candidates.append(b)

            if has_fc_src:
                # 사용자가 지정한 fullchain 안의 CA들을 후보로
                _collect_from(os.path.join(path, std_fc))
            else:
                # 폴더 내 CA/체인 파일에서 수집
                for fname in sorted(os.listdir(path)):
                    fp = os.path.join(path, fname)
                    if not os.path.isfile(fp) or fname in (std_fc, std_cert) or fname.lower().endswith(('.pfx', '.key')):
                        continue
                    if _classify_pem_file(fp, base) in ('ca', 'fullchain'):
                        _collect_from(fp)

            # 표준 체인(루트 제외, 순서 정렬) 구성
            chain = _build_standard_chain(leaf_pem, ca_candidates)
            with open(os.path.join(path, std_fc), 'w') as out:
                out.write(leaf_pem if leaf_pem.endswith('\n') else leaf_pem + '\n')
                out.write(''.join(chain))
            has_fc = True
            if not chain:
                logger.warning(f"Manual cert {base}: fullchain has leaf only (no intermediate CA found).")
        except Exception as e:
            logger.error(f"Manual cert {base}: standard fullchain build failed: {e}")
            has_fc = has_fc_src  # 실패 시 원본 fullchain이라도 유지

    if not (has_key and has_cert and has_fc):
        missing = [n for n, ok in [('key', has_key), ('cert', has_cert), ('fullchain', has_fc)] if not ok]
        return False, _("Missing files: {missing}").format(missing=", ".join(missing))

    ensure_rootca_exists(cert, force=True)

    # 중간 CA 체인(<base>_chain.cer): 사용자가 chain 파일을 지정하면 그 안의 중간 CA만 표준화,
    # 미지정이면 fullchain 등에서 자동 추출.
    std_chain = f"{base}_chain.cer"
    chain_made = False
    if chain_file:
        src = os.path.join(path, chain_file)
        if os.path.exists(src):
            try:
                inter = []
                seen = set()
                with open(src, 'r', errors='ignore') as f:
                    for b in _split_pem_certs(f.read()):
                        info = _analyze_cert_block(b)
                        if info and info['is_ca'] and not info['self_signed']:
                            key = (info['subject'], info['issuer'])
                            if key not in seen:
                                seen.add(key)
                                inter.append(b)
                if inter:
                    with open(os.path.join(path, std_chain), 'w') as out:
                        out.write(''.join(inter))
                    chain_made = True
            except Exception as e:
                logger.error(f"Manual cert {base}: chain build from '{chain_file}' failed: {e}")
    if not chain_made:
        ensure_chain_exists(cert, force=True)  # Apache SSLCertificateChainFile용 중간 CA 자동 추출

    update_certificate_info(cert)
    cert.save()
    if ensure_pfx_exists(cert):
        return True, _("Manual certificate finalized and PFX generated.")
    return True, _("Manual certificate finalized (PFX generation skipped — check files).")


def sync_certificates(request):
    acme_path = '/app/acme.sh'
    count = 0
    if os.path.exists(acme_path):
        for item in os.listdir(acme_path):
            full_path = os.path.join(acme_path, item)
            if os.path.isdir(full_path) and not item.startswith('.') and item not in ['deploy', 'dnsapi', 'notify', 'ca']:
                cert, created = Certificate.objects.update_or_create(cert_path=full_path, defaults={'domain': item.replace('_ecc', '')})
                update_certificate_info(cert, sync_wildcard=True); cert.save(); count += 1
    messages.success(request, _("{count} certificates synchronized.").format(count=count))
    return redirect('core_cert:certificate_list')

def trigger_cron_renew(request):
    from django.core.management import call_command
    import threading
    threading.Thread(target=lambda: call_command('cron_renew')).start()
    messages.success(request, _("Full renewal and deployment process started in the background."))
    return redirect(request.META.get('HTTP_REFERER', 'core_cert:certificate_list'))

def setup_renewal_hook(request, pk):
    cert = get_object_or_404(Certificate, pk=pk)
    cert_home = os.path.dirname(cert.cert_path) if cert.cert_path else '/app/acme.sh'
    cmd = ['acme.sh', '--home', '/app/acme.sh']
    if cert_home and cert_home != '/app/acme.sh':
        cmd += ['--cert-home', cert_home]
    cmd += ['--install-cert', '-d', cert.domain, '--reloadcmd', f'python3 /app/manage.py deploy_domain {cert.domain} --cert-id {cert.pk}']
    if cert.key_type == 'ec-256': cmd.append('--ecc')
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0: messages.success(request, _("{domain} deployment hook setup completed.").format(domain=cert.domain))
        else: messages.error(request, _("Failed: {error}").format(error=res.stderr))
    except Exception as e: messages.error(request, _("Error: {error}").format(error=str(e)))
    return redirect('core_cert:certificate_list')

class CertificateListView(ListView):
    model = Certificate; template_name = 'core_cert/certificate_list.html'; context_object_name = 'certs'
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['global_settings'] = {s.key: s.value for s in GlobalSetting.objects.all()}
        from datetime import timedelta
        r_time = context['global_settings'].get('RENEWAL_TIME', '03:00')
        try:
            now = timezone.now()
            target = timezone.make_aware(dt_class.strptime(r_time, '%H:%M').replace(year=now.year, month=now.month, day=now.day))
            if target < now: target += timedelta(days=1)
            diff = target - now; hh, rem = divmod(diff.seconds, 3600); mm, remainder = divmod(rem, 60)
            context['next_renewal_remaining'] = _("{hh}h {mm}m left").format(hh=hh, mm=mm)
        except: context['next_renewal_remaining'] = _("Calculation failed")
        return context

class CertificateCreateView(CreateView):
    model = Certificate; form_class = CertificateForm; template_name = 'core_cert/certificate_form.html'; success_url = reverse_lazy('core_cert:certificate_list')
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs); acme_path = '/app/acme.sh'; dirs = []
        if os.path.exists(acme_path):
            for d in os.listdir(acme_path):
                if os.path.isdir(os.path.join(acme_path, d)) and not d.startswith('.') and d not in ['deploy', 'dnsapi', 'notify', 'ca']:
                    dirs.append({'name': d, 'path': os.path.join(acme_path, d)})
        context['acme_dirs'] = dirs; return context
    def form_valid(self, form):
        cert_type = form.cleaned_data.get('cert_type')
        self.object = form.save(commit=False)
        if cert_type == 'manual':
            # 수동 인증서: acme.sh가 관리하지 않음 → 자동 갱신 대상에서 제외
            self.object.is_acme = False
            self.object.status = 'unknown'
            self.object.save()
            uploaded = form.cleaned_data.get('upload_zip')
            if uploaded:
                ok, msg = extract_manual_zip(self.object, uploaded)
                if ok:
                    messages.success(self.request, _("ZIP extracted. Please assign the certificate files below."))
                else:
                    messages.error(self.request, _("ZIP extraction failed: {error}").format(error=msg))
            # 수정 페이지로 리디렉션하여 파일 지정 진행
            return redirect('core_cert:certificate_edit', pk=self.object.pk)
        else:
            self.object.is_acme = True
            self.object.save()
            update_certificate_info(self.object); self.object.save()
            return super().form_valid(form)

class CertificateUpdateView(UpdateView):
    model = Certificate; form_class = CertificateForm; template_name = 'core_cert/certificate_form.html'; success_url = reverse_lazy('core_cert:certificate_list')
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['scripts'] = self.object.deploy_scripts.all()
        if self.object.cert_type == 'manual':
            detected = detect_manual_files(self.object)
            context['manual_files'] = detected['files']
            context['manual_guess'] = detected['guess']
            # 현재 적용된 표준 파일 존재 여부
            context['manual_current'] = {
                'key': self.object.get_source_file('key'),
                'cert': self.object.get_source_file('cert'),
                'fullchain': self.object.get_source_file('fullchain'),
                'chain': self.object.get_source_file('chain'),
                'pfx': self.object.get_source_file('pfx'),
            }
            context['old_backup'] = get_old_backup_info(self.object)
        return context
    def form_valid(self, form):
        cert_type = form.cleaned_data.get('cert_type')
        self.object = form.save(commit=False)
        if cert_type == 'manual':
            self.object.is_acme = False
            self.object.save()
            # 새 ZIP이 추가 업로드되면 다시 해제
            uploaded = form.cleaned_data.get('upload_zip')
            if uploaded:
                ok, msg = extract_manual_zip(self.object, uploaded)
                if ok:
                    messages.success(self.request, _("New ZIP extracted."))
                else:
                    messages.error(self.request, _("ZIP extraction failed: {error}").format(error=msg))
                return redirect('core_cert:certificate_edit', pk=self.object.pk)
            # 파일 지정값 처리
            key_file = self.request.POST.get('manual_key', '').strip()
            cert_file = self.request.POST.get('manual_cert', '').strip()
            fullchain_file = self.request.POST.get('manual_fullchain', '').strip()
            chain_file = self.request.POST.get('manual_chain', '').strip()
            if key_file or fullchain_file:
                ok, msg = finalize_manual_cert(self.object, key_file, cert_file, fullchain_file, chain_file)
                if ok:
                    messages.success(self.request, msg)
                    return redirect('core_cert:certificate_list')
                else:
                    messages.error(self.request, msg)
                    return redirect('core_cert:certificate_edit', pk=self.object.pk)
            return super().form_valid(form)
        else:
            self.object.is_acme = True
            self.object.save()
            update_certificate_info(self.object); self.object.save()
            return super().form_valid(form)

# --- Server Management ---

class ServerListView(ListView):
    model = TargetServer
    template_name = 'core_cert/server_list.html'
    context_object_name = 'servers'
    
    def get_queryset(self):
        queryset = super().get_queryset()
        sort = self.request.GET.get('sort', 'name')
        if sort == 'ip':
            return queryset.order_by('ip_address')
        elif sort == 'os':
            return queryset.order_by('os_type', 'web_server_type')
        return queryset.order_by('name')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['current_sort'] = self.request.GET.get('sort', 'name')
        return context
class ServerCreateView(CreateView): model = TargetServer; form_class = TargetServerForm; template_name = 'core_cert/server_form.html'; success_url = reverse_lazy('core_cert:server_list')
class ServerUpdateView(UpdateView): model = TargetServer; form_class = TargetServerForm; template_name = 'core_cert/server_form.html'; success_url = reverse_lazy('core_cert:server_list')

def server_delete(request, pk):
    server = get_object_or_404(TargetServer, pk=pk)
    if request.method == 'POST': server.delete(); messages.success(request, _("Server '{name}' deleted.").format(name=server.name)); return redirect('core_cert:server_list')
    return render(request, 'core_cert/confirm_delete.html', {'object': server, 'title': _('Delete Server'), 'cancel_url': reverse_lazy('core_cert:server_list')})

def test_ssh_connection(request, pk):
    server = get_object_or_404(TargetServer, pk=pk)
    from .ssh_manager import SSHManager
    mgr = SSHManager(server.ip_address, server.ssh_user, server.ssh_port)
    success, msg = mgr.test_connection()
    server.ssh_status = 'success' if success else 'failure'
    server.last_tested = timezone.now(); server.save()
    if success: messages.success(request, _("SSH connection successful: {name}").format(name=server.name))
    else: messages.error(request, _("SSH connection failed: {error}").format(error=msg))
    return redirect('core_cert:server_list')

def server_docker_ps(request, pk):
    """대상 서버에 SSH로 접속해 `docker ps`를 실행하고, 실행 중인 컨테이너 목록을 JSON으로 반환한다.
    배포 단계 설정의 '도커 컨테이너 재시작' 새로고침에서 사용. (Linux & Windows 공통)"""
    server = get_object_or_404(TargetServer, pk=pk)
    fmt = '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}'
    cmd = f'docker ps --format "{fmt}"'
    try:
        deployer = RemoteDeployer(server.ip_address, server.ssh_user, server.ssh_port)
        deployer.connect()
        status, out, err = deployer.execute_command(cmd)
        deployer.close()
    except Exception as e:
        return JsonResponse({'ok': False, 'error': str(e)}, status=200)

    if status != 0:
        # docker 미설치/권한 문제 등
        return JsonResponse({'ok': False, 'error': err or out or 'docker ps failed'}, status=200)

    containers = []
    for line in (out or '').splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split('|')
        if len(parts) < 4:
            continue
        containers.append({
            'id': parts[0],
            'name': parts[1],
            'image': parts[2],
            'status': parts[3],
        })
    return JsonResponse({'ok': True, 'containers': containers})

def server_ssh_setup(request, pk):
    server = get_object_or_404(TargetServer, pk=pk)
    if request.method == 'POST':
        from .ssh_manager import SSHManager
        mgr = SSHManager(server.ip_address, server.ssh_user, server.ssh_port)
        success, msg = mgr.setup_ssh_key(request.POST.get('password'), os_type=server.os_type)
        if success: messages.success(request, _("SSH key registered successfully")); server.ssh_status = 'success'; server.save()
        else: messages.error(request, _("Registration failed: {error}").format(error=msg))
        return redirect('core_cert:server_list')
    return render(request, 'core_cert/server_ssh_setup.html', {'server': server})

def ssh_key_manage(request):
    from .ssh_manager import get_public_keys, regenerate_keys, save_ssh_key
    if request.method == 'POST':
        if 'regenerate' in request.POST: regenerate_keys(); messages.success(request, _("Regeneration completed"))
        elif 'save_manual' in request.POST:
            pk, pub = request.POST.get('private_key'), request.POST.get('public_key')
            if pk: save_ssh_key(pk, pub); messages.success(request, _("Saved successfully"))
        return redirect('core_cert:ssh_key_manage')
    return render(request, 'core_cert/ssh_key_manage.html', {'public_keys': get_public_keys()})

# --- Dashboard & Logs ---

def dashboard(request):
    from datetime import timedelta
    now = timezone.now(); thirty_days = now + timedelta(days=30)
    certs = Certificate.objects.all()
    servers = TargetServer.objects.all()
    unresolved_fail_logs = DeploymentLog.objects.filter(status__in=['failure', 'partial_success'], is_resolved=False).order_by('-started_at')
    return render(request, 'core_cert/dashboard.html', {
        'certs_count': certs.count(), 'expiring_soon': certs.filter(expiry_date__lte=thirty_days, expiry_date__gt=now).count(),
        'expired_count': certs.filter(expiry_date__lte=now).count(), 'servers_count': servers.count(),
        'server_fail_count': servers.filter(ssh_status='failure').count(), 'scripts': DeployScript.objects.all(),
        'recent_logs': DeploymentLog.objects.order_by('-started_at')[:10], 'unresolved_fail_logs': unresolved_fail_logs,
        'deploy_fail_count': unresolved_fail_logs.count(),
    })

def resolve_log(request, pk):
    log = get_object_or_404(DeploymentLog, pk=pk); log.is_resolved = True; log.save()
    messages.success(request, _("Marked as resolved.")); return redirect('core_cert:dashboard')

def delete_log(request, pk):
    log = get_object_or_404(DeploymentLog, pk=pk); log.delete(); messages.success(request, _("Deleted successfully"))
    next_url = request.GET.get('next', 'core_cert:dashboard'); return redirect(next_url if next_url.startswith('/') else 'core_cert:dashboard')

def bulk_log_action(request):
    if request.method == 'POST':
        log_ids, action = request.POST.getlist('log_ids'), request.POST.get('action_type')
        next_url = request.POST.get('next', 'core_cert:dashboard')
        if log_ids:
            logs = DeploymentLog.objects.filter(pk__in=log_ids)
            if action == 'resolve': logs.update(is_resolved=True); messages.success(request, _("{count} items marked as resolved.").format(count=logs.count()))
            elif action == 'delete': count = logs.count(); logs.delete(); messages.success(request, _("{count} items deleted.").format(count=count))
        return redirect(next_url if next_url.startswith('/') else 'core_cert:dashboard')
    return redirect('core_cert:dashboard')

# --- Site Verification ---

# IIS의 시작된 사이트에서 https 바인딩(호스트:포트)을 조회하는 PowerShell 명령.
# test_sites_verification(서버 관리 '사이트 테스트')과 deploy_domain(배포 후 검증)에서 공용으로 사용한다.
IIS_DISCOVER_SITES_PS = (
    'powershell -Command "Import-Module WebAdministration; '
    'Get-ChildItem -Path IIS:\\Sites | Where-Object { $_.State -eq \'Started\' } | '
    'ForEach-Object { $_.Bindings.Collection | Where-Object { $_.protocol -eq \'https\' } | '
    'ForEach-Object { \'{0}:{1}\' -f $_.bindingInformation.Split(\':\')[1], $_.bindingInformation.Split(\':\')[-1] } } | '
    'Where-Object { $_ -ne \':\' }"'
)


def discover_iis_sites(deployer):
    """원격 IIS에서 시작된 사이트의 https 바인딩을 조회해 [(domain, port), ...] 로 반환한다.
    deployer 는 이미 connect() 된 RemoteDeployer 여야 한다. 실패 시 빈 리스트."""
    results = []
    status, out, err = deployer.execute_command(IIS_DISCOVER_SITES_PS)
    if status == 0 and out:
        for line in out.split('\n'):
            line = line.strip()
            if ':' in line:
                p_str, d_name = line.split(':', 1)
                if d_name:
                    results.append((d_name, int(p_str) if p_str.isdigit() else 443))
    return results


def extract_domains_from_config(content, web_server_type):
    results = []
    if web_server_type == 'apache':
        vh_blocks = re.findall(r'<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>', content, re.DOTALL | re.IGNORECASE)
        for vh_header, vh_content in vh_blocks:
            # 제외 주석 확인
            if '# AgnCERT_except=true' in vh_content:
                continue
                
            port = 443
            if ':' in vh_header:
                p_match = re.search(r':(\d+)', vh_header)
                if p_match: port = int(p_match.group(1))
            for line in vh_content.split('\n'):
                line = line.strip()
                # 주석 라인은 건너뛴다 (예: #ServerName ...)
                if line.startswith('#'):
                    continue
                if line.lower().startswith('servername') or line.lower().startswith('serveralias'):
                    parts = line.split()
                    if len(parts) > 1:
                        for d in parts[1:]:
                            domain = d.strip(';').strip('"').strip("'")
                            # 'ServerName host:443' 처럼 포트가 붙은 경우 호스트와 포트를 분리한다.
                            entry_port = port
                            if ':' in domain:
                                host_part, sep, port_part = domain.rpartition(':')
                                if host_part and port_part.isdigit():
                                    domain = host_part
                                    entry_port = int(port_part)
                            if domain in ['localhost', '127.0.0.1', '::1'] or not domain:
                                continue
                            if not any(c in domain for c in ['$', '{', '}', ':']):
                                results.append((domain, entry_port))
    elif web_server_type == 'nginx':
        # server { 를 기준으로 분할하여 각 블록을 처리 (더 견고한 방식)
        parts = re.split(r'server\s*\{', content)
        for block in parts[1:]:
            # 제외 주석 확인
            if '# AgnCERT_except=true' in block:
                continue
                
            port = 443
            l_match = re.search(r'listen\s+(\d+)\s+ssl', block, re.IGNORECASE)
            if l_match: port = int(l_match.group(1))
            
            sn_match = re.search(r'server_name\s+([^;]+);', block, re.IGNORECASE)
            if sn_match:
                for n in sn_match.group(1).split():
                    domain = n.strip().strip('"').strip("'")
                    # _ , localhost, IP 등 실제 도메인이 아닌 경우 제외
                    if domain in ['_', 'localhost', '127.0.0.1', '::1'] or not domain:
                        continue
                    if not any(c in domain for c in ['$', '{', '}', ':']):
                        results.append((domain, port))
    return list(set(results))

def test_sites_verification(request, pk):
    server = get_object_or_404(TargetServer, pk=pk); results = []
    managed_targets = DeploymentTarget.objects.filter(server=server)
    managed_domain_names = set()
    for t in managed_targets:
        managed_domain_names.add(t.script.certificate.domain)
        if t.script.certificate.allowed_domains: managed_domain_names.update([d.strip() for d in re.split(r'[, \n]+', t.script.certificate.allowed_domains) if d.strip()])
    config_results = []
    deployer = None
    try:
        deployer = RemoteDeployer(host=server.ip_address, user=server.ssh_user, port=server.ssh_port); deployer.connect()
        if server.os_type == 'linux' and server.ssl_config_path:
            status, out, err = deployer.execute_command(f'cat {server.ssl_config_path}')
            if status == 0 and out: config_results = extract_domains_from_config(out, server.web_server_type)
        elif server.os_type == 'windows':
            config_results = discover_iis_sites(deployer)
        if config_results:
            TargetServerSite.objects.filter(server=server).delete()
            for d_name, p_num in list(set(config_results)): TargetServerSite.objects.create(server=server, domain=d_name, port=p_num)
    except Exception: config_results = [(s.domain, s.port) for s in TargetServerSite.objects.filter(server=server)]
    finally:
        if deployer: deployer.close()
    all_certs = list(Certificate.objects.all().order_by('-expiry_date'))
    kst = timezone.get_fixed_timezone(540)
    for domain_name, port_num in config_results:
        test_domain = domain_name.replace('*.', '')
        v_info = verify_site_certificate(test_domain, port=port_num)
        is_managed = domain_name in managed_domain_names
        if not is_managed:
            for m_dn in managed_domain_names:
                if m_dn.startswith('*.'):
                    if domain_name.endswith('.' + m_dn[2:]) or domain_name == m_dn[2:]: is_managed = True; break

        # 도메인에 해당하는 후보 cert 목록 수집 (동일 도메인 여러 개 대응)
        candidate_certs = []
        for cert_obj in all_certs:
            if cert_obj.domain == domain_name or cert_obj.domain == f'*.{domain_name}':
                candidate_certs.append(cert_obj)
            elif cert_obj.allowed_domains and domain_name in [d.strip() for d in re.split(r'[, \n]+', cert_obj.allowed_domains)]:
                candidate_certs.append(cert_obj)
            elif cert_obj.is_wildcard and (domain_name.endswith('.' + cert_obj.domain.replace('*.', '')) or domain_name == cert_obj.domain.replace('*.', '')):
                candidate_certs.append(cert_obj)

        matched_cert = candidate_certs[0] if candidate_certs else None
        res = {'domain': f"{domain_name}:{port_num}" if port_num != 443 else domain_name, 'is_managed': is_managed, 'verified': False, 'match': False, 'matched_cert_name': (matched_cert.name or matched_cert.domain) if matched_cert else None}
        if v_info:
            res['verified'] = True; v_expiry, v_serial = v_info['expiry_date'], v_info.get('serial', '').replace(':', '').upper(); res['serial'] = v_serial
            if v_expiry: res['expiry_date'] = v_expiry.astimezone(kst).strftime('%Y-%m-%d %H:%M')
            if is_managed and candidate_certs:
                # 시리얼로 정확히 매칭되는 cert 우선 선택
                for c in candidate_certs:
                    if not c.serial: update_certificate_info(c); c.save()
                    if c.serial and c.serial == v_serial:
                        matched_cert = c; res['match'] = True; break
                # 시리얼 미매칭 시 만료일로 재시도
                if not res['match']:
                    for c in candidate_certs:
                        if c.expiry_date and v_expiry:
                            if c.expiry_date.astimezone(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M') == v_expiry.astimezone(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M'):
                                matched_cert = c; res['match'] = True; break
                res['matched_cert_name'] = (matched_cert.name or matched_cert.domain) if matched_cert else None
                if matched_cert and matched_cert.expiry_date: res['db_expiry_date'] = matched_cert.expiry_date.astimezone(kst).strftime('%Y-%m-%d %H:%M')
            if not is_managed: res['status_text'] = '미관리'; res['match'] = False
            elif res['match']: res['status_text'] = '일치'
            else:
                res['status_text'] = '불일치'
                msg = f"Site mismatch: {domain_name}:{port_num} (Matched Cert: {matched_cert.domain if matched_cert else 'N/A'}, DB Expiry: {matched_cert.expiry_date if matched_cert else 'N/A'}, Site Expiry: {v_expiry}, Site Serial: {v_serial})"
                logger.error(f"[SiteMismatch] {msg}")
        else: res['status_text'] = '오류'; res['error'] = f'{port_num} 포트 접속 실패'
        results.append(res)
    results.sort(key=lambda x: x.get('is_managed', False), reverse=True)
    return JsonResponse({'results': results})

def test_sites_verification_bulk(request):
    server_ids = request.GET.getlist('server_ids')
    if not server_ids: return JsonResponse({'error': '선택 서버 없음'}, status=400)
    results = {}; kst = timezone.get_fixed_timezone(540); all_certs = Certificate.objects.all().order_by('-expiry_date')
    for server in TargetServer.objects.filter(pk__in=server_ids):
        server_results = []; config_results = []
        managed_domain_names = set()
        for t in DeploymentTarget.objects.filter(server=server):
            managed_domain_names.add(t.script.certificate.domain)
            if t.script.certificate.allowed_domains: managed_domain_names.update([d.strip() for d in re.split(r'[, \n]+', t.script.certificate.allowed_domains) if d.strip()])
        deployer = None
        try:
            deployer = RemoteDeployer(host=server.ip_address, user=server.ssh_user, port=server.ssh_port); deployer.connect()
            if server.os_type == 'linux' and server.ssl_config_path:
                status, out, err = deployer.execute_command(f'cat {server.ssl_config_path}')
                if status == 0 and out: config_results = extract_domains_from_config(out, server.web_server_type)
            elif server.os_type == 'windows':
                ps_cmd = 'powershell -Command "Import-Module WebAdministration; Get-ChildItem -Path IIS:\\Sites | Where-Object { $_.State -eq \'Started\' } | ForEach-Object { $_.Bindings.Collection | Where-Object { $_.protocol -eq \'https\' } | ForEach-Object { \'{0}:{1}\' -f $_.bindingInformation.Split(\':\')[1], $_.bindingInformation.Split(\':\')[-1] } } | Where-Object { $_ -ne \':\' }"'
                status, out, err = deployer.execute_command(ps_cmd)
                if status == 0 and out:
                    for line in out.split('\n'):
                        if ':' in line.strip():
                            p_str, d_name = line.strip().split(':', 1)
                            if d_name: config_results.append((d_name, int(p_str) if p_str.isdigit() else 443))
            if config_results:
                TargetServerSite.objects.filter(server=server).delete()
                for d_name, p_num in list(set(config_results)): TargetServerSite.objects.create(server=server, domain=d_name, port=p_num)
        except Exception: config_results = [(s.domain, s.port) for s in TargetServerSite.objects.filter(server=server)]
        finally:
            if deployer: deployer.close()
        for d_name, p_num in config_results:
            v_info = verify_site_certificate(d_name.replace('*.', ''), port=p_num); is_managed = d_name in managed_domain_names
            if not is_managed:
                for m_dn in managed_domain_names:
                    if m_dn.startswith('*.'):
                        if d_name.endswith('.' + m_dn[2:]) or d_name == m_dn[2:]: is_managed = True; break

            candidate_certs = []
            for cert_obj in all_certs:
                if cert_obj.domain == d_name or cert_obj.domain == f'*.{d_name}':
                    candidate_certs.append(cert_obj)
                elif cert_obj.allowed_domains and d_name in [x.strip() for x in re.split(r'[, \n]+', cert_obj.allowed_domains)]:
                    candidate_certs.append(cert_obj)
                elif cert_obj.is_wildcard and (d_name.endswith('.' + cert_obj.domain.replace('*.', '')) or d_name == cert_obj.domain.replace('*.', '')):
                    candidate_certs.append(cert_obj)

            matched_cert = candidate_certs[0] if candidate_certs else None
            res = {'domain': f"{d_name}:{p_num}" if p_num != 443 else d_name, 'port': p_num, 'is_managed': is_managed, 'verified': False, 'match': False}
            if v_info:
                res['verified'] = True; v_expiry, v_serial = v_info['expiry_date'], v_info.get('serial', '').replace(':', '').upper()
                if v_expiry: res['expiry_date'] = v_expiry.astimezone(kst).strftime('%Y-%m-%d %H:%M')
                if is_managed and candidate_certs:
                    for c in candidate_certs:
                        if c.serial and c.serial == v_serial:
                            matched_cert = c; res['match'] = True; break
                    if not res['match']:
                        for c in candidate_certs:
                            if c.expiry_date and v_expiry:
                                if c.expiry_date.astimezone(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M') == v_expiry.astimezone(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M'):
                                    matched_cert = c; res['match'] = True; break
                if not is_managed: res['status_text'] = '미관리'
                elif res['match']: res['status_text'] = '일치'
                else:
                    res['status_text'] = '불일치'
                    msg = f"Site mismatch (bulk): {d_name}:{p_num} (Server: {server.name}, Matched Cert: {matched_cert.domain if matched_cert else 'N/A'}, DB Expiry: {matched_cert.expiry_date if matched_cert else 'N/A'}, Site Expiry: {v_expiry}, Site Serial: {v_serial})"
                    logger.error(f"[SiteMismatchBulk] {msg}")
            else: res['status_text'] = '오류'; res['error'] = f'{p_num} 접속 실패'
            server_results.append(res)
        server_results.sort(key=lambda x: x.get('is_managed', False), reverse=True)
        results[server.name] = server_results
    return JsonResponse({'results': results})

def bulk_server_delete(request):
    if request.method == 'POST':
        server_ids = request.POST.getlist('server_ids')
        if server_ids: TargetServer.objects.filter(pk__in=server_ids).delete(); messages.success(request, "삭제 완료")
    return redirect('core_cert:server_list')

# --- Deployment Script Management ---

DeploymentTargetFormSet = inlineformset_factory(DeployScript, DeploymentTarget, form=DeploymentTargetForm, extra=0, can_delete=True)
FileMappingFormSet = inlineformset_factory(DeploymentTarget, FileMapping, form=FileMappingForm, extra=0, can_delete=True)

class ScriptListView(ListView): model = DeployScript; template_name = 'core_cert/script_list.html'; context_object_name = 'scripts'

class ScriptCreateView(CreateView):
    model = DeployScript; form_class = DeployScriptForm; template_name = 'core_cert/script_form.html'; success_url = reverse_lazy('core_cert:script_list')
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.POST: fs = DeploymentTargetFormSet(self.request.POST); context['formset'] = fs; context['formset_mappings'] = [(f, FileMappingFormSet(self.request.POST, prefix=f"{f.prefix}-file_mappings")) for f in fs]
        else: fs = DeploymentTargetFormSet(); context['formset'] = fs; context['formset_mappings'] = [(f, FileMappingFormSet(prefix=f"{f.prefix}-file_mappings")) for f in fs]
        context['servers'] = TargetServer.objects.all(); context['server_data'] = {str(s.id): {'name': s.name, 'os_type': s.os_type} for s in context['servers']}
        context['cert_source_files'] = build_cert_source_file_map(form); return context
    def form_valid(self, form):
        ctx = self.get_context_data(); fs, fsm = ctx['formset'], ctx['formset_mappings']
        if form.is_valid() and fs.is_valid():
            self.object = form.save(); fs.instance = self.object; fs.save()
            for tf, mf in fsm:
                if mf.is_valid() and not tf.cleaned_data.get('DELETE'): mf.instance = tf.instance; mf.save()
            return redirect(self.get_success_url())
        return self.render_to_response(self.get_context_data(form=form))

class ScriptUpdateView(UpdateView):
    model = DeployScript; form_class = DeployScriptForm; template_name = 'core_cert/script_form.html'; success_url = reverse_lazy('core_cert:script_list')
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.POST: fs = DeploymentTargetFormSet(self.request.POST, instance=self.object); context['formset'] = fs; context['formset_mappings'] = [(f, FileMappingFormSet(self.request.POST, prefix=f"{f.prefix}-file_mappings", instance=f.instance)) for f in fs]
        else: fs = DeploymentTargetFormSet(instance=self.object); context['formset'] = fs; context['formset_mappings'] = [(f, FileMappingFormSet(prefix=f"{f.prefix}-file_mappings", instance=f.instance)) for f in fs]
        context['servers'] = TargetServer.objects.all()
        context['cert_source_files'] = build_cert_source_file_map(context.get('form')); return context
    def form_valid(self, form):
        ctx = self.get_context_data(); fs, fsm = ctx['formset'], ctx['formset_mappings']
        if form.is_valid() and fs.is_valid():
            self.object = form.save(); fs.instance = self.object; fs.save()
            for tf, mf in fsm:
                if mf.is_valid() and not tf.cleaned_data.get('DELETE'): mf.instance = tf.instance; mf.save()
            return redirect(self.get_success_url())
        return self.render_to_response(self.get_context_data(form=form))

def script_detail(request, pk): script = get_object_or_404(DeployScript, pk=pk); return render(request, 'core_cert/script_detail.html', {'script': script, 'logs': DeploymentLog.objects.filter(script=script).order_by('-started_at')})

def certificate_action_view(request, pk, action, title): cert = get_object_or_404(Certificate, pk=pk); return render(request, 'core_cert/certificate_action.html', {'cert': cert, 'action': action, 'title': title})
def certificate_issue(request, pk): return certificate_action_view(request, pk, 'issue', '인증서 신규 발급')
def certificate_test_issue(request, pk): return certificate_action_view(request, pk, 'test_issue', '인증서 테스트 발급')
def certificate_renew(request, pk): return certificate_action_view(request, pk, 'renew', '인증서 갱신')

def certificate_delete(request, pk):
    cert = get_object_or_404(Certificate, pk=pk)
    if request.method == 'POST':
        delete_files = request.POST.get('delete_files') == 'on'
        if delete_files and cert.cert_path and os.path.exists(cert.cert_path):
            import shutil
            try:
                shutil.rmtree(cert.cert_path)
                messages.success(request, _("Certificate files for {domain} have been deleted.").format(domain=cert.domain))
            except Exception as e:
                messages.error(request, _("Error deleting files: {error}").format(error=str(e)))
        
        cert.delete()
        messages.success(request, _("Certificate {domain} removed from database.").format(domain=cert.domain))
        return redirect('core_cert:certificate_list')
    
    return render(request, 'core_cert/confirm_delete.html', {
        'object': cert, 
        'title': _('Delete Certificate'), 
        'cancel_url': reverse_lazy('core_cert:certificate_list'),
        'is_certificate': True
    })

def script_delete(request, pk):
    script = get_object_or_404(DeployScript, pk=pk)
    if request.method == 'POST': script.delete(); return redirect('core_cert:script_list')
    return render(request, 'core_cert/confirm_delete.html', {'object': script, 'title': '배포 스크립트 삭제', 'cancel_url': reverse_lazy('core_cert:script_list')})

def get_cname_info(request, pk):
    cert = get_object_or_404(Certificate, pk=pk); base = cert.domain.replace('*.', ''); conf = os.path.join(cert.cert_path, f"{base}.conf") if cert.cert_path else os.path.join('/app/acme.sh', f"{base}_ecc", f"{base}.conf")
    if not os.path.exists(conf): return JsonResponse({'error': '설정 파일 없음'}, status=404)
    sub = None
    with open(conf, 'r') as f:
        for line in f:
            if 'ACMEDNS_SUBDOMAIN' in line: sub = line.split('=', 1)[1].strip().strip("'").strip('"'); break
    if not sub: return JsonResponse({'error': 'acme-dns 정보 없음'}, status=404)
    host = GlobalSetting.get_value('ACMEDNS_CNAME_DOMAIN')
    placeholder = False
    if not host: 
        host = "auth.example.com"
        placeholder = True
    return JsonResponse({'domain': f'_acme-challenge.{base}', 'cname_target': f'{sub}.{host}', 'is_placeholder': placeholder})


def regenerate_cert_files(request, pk):
    """인증서 폴더의 파생 파일(chain / RootCA / pfx)을 발급된 원본 기준으로 재생성한다.
    ZeroSSL이면 구형 기기 호환용 cross-sign 변형(chain_AAA / chain_USERTRUST)도 함께 만든다.
    배포 전 파일을 최신화하거나 누락 파일을 복구할 때 수동으로 호출한다."""
    cert = get_object_or_404(Certificate, pk=pk)
    if not cert.cert_path or not os.path.exists(cert.cert_path):
        return JsonResponse({'error': '인증서 경로가 없습니다. 먼저 발급하세요.'}, status=400)
    results = []
    # 1) 중간 CA 체인
    name = ensure_chain_exists(cert, force=True)
    results.append({'file': name or f"{cert.domain.replace('*.', '')}_chain.cer", 'ok': bool(name), 'label': 'Intermediate chain'})
    # 2) Root CA 번들
    name = ensure_rootca_exists(cert, force=True)
    results.append({'file': name or f"{cert.domain.replace('*.', '')}_RootCA.pem", 'ok': bool(name), 'label': 'Root CA chain'})
    # 3) PFX
    ok_pfx = ensure_pfx_exists(cert)
    results.append({'file': f"{cert.domain.replace('*.', '')}.pfx", 'ok': bool(ok_pfx), 'label': 'PFX'})
    # 4) ZeroSSL 한정: 구형 기기 호환 cross-sign 변형
    if cert.ca_server == 'zerossl':
        for variant in ('aaa', 'usertrust'):
            vname = ensure_chain_variant_exists(cert, variant, force=True)
            results.append({'file': vname or f"{cert.domain.replace('*.', '')}_chain_{variant.upper()}.cer",
                            'ok': bool(vname), 'label': f'Legacy chain ({variant.upper()})'})
    return JsonResponse({'results': results})


def restore_manual_cert(request, pk):
    """수동 인증서의 직전 백업(_old)으로 복구한다. (POST 전용)"""
    cert = get_object_or_404(Certificate, pk=pk)
    if request.method != 'POST':
        return JsonResponse({'error': _('Invalid request method.')}, status=405)
    if cert.cert_type != 'manual':
        return JsonResponse({'error': _('Only manual certificates can be restored.')}, status=400)
    ok, msg = restore_manual_cert_files(cert)
    if not ok:
        if msg == 'no_backup':
            return JsonResponse({'error': _('There is no previous certificate to restore.')}, status=400)
        return JsonResponse({'error': _('Restore failed: {error}').format(error=msg)}, status=500)
    # 복구된 파일 기준으로 DB 정보(만료일/시리얼) 갱신
    try:
        update_certificate_info(cert); cert.save()
    except Exception:
        pass
    return JsonResponse({'ok': True, 'message': _('Restored to the previous certificate.')})

import os
import subprocess
import re
from datetime import datetime

from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic import ListView, CreateView, UpdateView
from django.urls import reverse_lazy
from django.utils import timezone
from django.contrib import messages
from django.forms import inlineformset_factory

from .models import Certificate, DeployScript, DeploymentLog, TargetServer, GlobalSetting, DeploymentTarget, FileMapping
from .forms import CertificateForm, DeployScriptForm, DeploymentTargetForm, FileMappingForm, TargetServerForm
from . import ssh_manager

# --- Global Settings ---

def save_global_settings(request):
    if request.method == 'POST':
        key = request.POST.get('key')
        value = request.POST.get('value')
        if key and value:
            GlobalSetting.set_value(key, value)
            messages.success(request, f"설정({key})이 저장되었습니다.")
        return redirect(request.META.get('HTTP_REFERER', 'core_cert:settings'))
    return redirect('core_cert:settings')

def global_settings_view(request):
    return render(request, 'core_cert/settings.html')

# --- Certificate Management ---

def update_certificate_info(instance, sync_wildcard=False):
    """인증서 파일에서 만료일과 상태를 자동으로 감지하여 업데이트합니다."""
    if not instance.cert_path:
        return

    domain_name = instance.domain
    full_path = instance.cert_path
    
    cert_file = None
    # Try to find the certificate file
    cert_file_name = instance.get_source_file('fullchain') or instance.get_source_file('cert')
    if cert_file_name:
        cert_file = os.path.join(full_path, cert_file_name)
    else:
        cert_file = None

    if cert_file:
        try:
            output = subprocess.check_output(
                ['openssl', 'x509', '-text', '-noout', '-in', cert_file],
                stderr=subprocess.STDOUT, universal_newlines=True
            )
            
            expiry_date = None
            for line in output.split('\n'):
                if 'Not After :' in line:
                    date_str = line.split(':', 1)[1].strip()
                    try:
                        expiry_date = timezone.make_aware(datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z'))
                    except Exception:
                        expiry_date = timezone.make_aware(datetime.strptime(date_str, '%b %d %H:%M:%S %Y'))
                    break
            
            if expiry_date:
                instance.expiry_date = expiry_date
                instance.status = 'expired' if expiry_date < timezone.now() else 'valid'

            file_is_wildcard = '*.' in output
            if sync_wildcard:
                instance.is_wildcard = file_is_wildcard
            elif file_is_wildcard:
                instance.is_wildcard = True
            
            domains = set()
            san_match = re.search(r"X509v3 Subject Alternative Name:.*?(\n\s+DNS:.*)+", output, re.DOTALL)
            if san_match:
                san_section = san_match.group(0)
                dns_names = re.findall(r"DNS:([^\s,]+)", san_section)
                domains.update(dns_names)
            
            cn_match = re.search(r"Subject:.*?CN\s*=\s*([^\s,/]+)", output)
            if cn_match:
                domains.add(cn_match.group(1))
            
            instance.allowed_domains = ", ".join(sorted(list(domains)))
            
        except Exception as e:
            print(f"Error parsing cert {instance.domain}: {e}")
            instance.status = 'unknown'

def find_source_file(cert, file_type):
    """인증서 폴더 내에서 실제 파일 시스템을 조사하여 가장 적절한 소스 파일을 찾습니다."""
    return cert.get_source_file(file_type)

def ensure_pfx_exists(cert):
    """Windows 배포를 위해 .pem/.cer 파일들을 하나의 .pfx 파일로 합칩니다."""
    if not cert.cert_path or not os.path.exists(cert.cert_path):
        return False
    
    base_domain = cert.domain.replace('*.', '')
    pfx_path = os.path.join(cert.cert_path, f"{base_domain}.pfx")
    
    # 가능한 파일들 찾기
    key_file_name = cert.get_source_file('key')
    cert_file_name = cert.get_source_file('cert')
    fullchain_file_name = cert.get_source_file('fullchain')

    if not all([key_file_name, cert_file_name, fullchain_file_name]):
        return False
    
    key_file = os.path.join(cert.cert_path, key_file_name)
    cert_file = os.path.join(cert.cert_path, cert_file_name)
    fullchain_file = os.path.join(cert.cert_path, fullchain_file_name)
    
    try:
        # OpenSSL 3.x compatibility for Windows: use -legacy and -descert
        cmd = [
            'openssl', 'pkcs12', '-export', '-out', pfx_path,
            '-inkey', key_file, '-in', cert_file,
            '-certfile', fullchain_file, '-passout', 'pass:password',
            '-legacy', '-descert'
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except Exception as e:
        print(f"PFX generation failed for {cert.domain}: {e}")
        return False

def sync_certificates(request):
    cert_sources = [('/app/acme.sh', 'acme')]
    count = 0
    for root_path, source_type in cert_sources:
        if not os.path.exists(root_path): continue
        for item in os.listdir(root_path):
            full_path = os.path.join(root_path, item)
            if not os.path.isdir(full_path) or item.startswith('.') or item in ['deploy', 'dnsapi', 'notify', 'ca']:
                continue
            
            domain_name = item.replace('_ecc', '')
            cert, created = Certificate.objects.update_or_create(
                domain=item,
                defaults={'cert_path': full_path}
            )
            if cert.cert_path != full_path:
                cert.cert_path = full_path
            
            update_certificate_info(cert, sync_wildcard=True)
            cert.save()
            if created: count += 1
            
            if DeployScript.objects.filter(certificate=cert).exists():
                try:
                    cmd = ['acme.sh', '--home', '/app/acme.sh', '--install-cert', '-d', cert.domain, '--reloadcmd', f'python3 /app/manage.py deploy_domain {cert.domain}']
                    if '_ecc' in cert.cert_path: cmd.append('--ecc')
                    subprocess.run(cmd, capture_output=True)
                except Exception: pass
    
    messages.success(request, f"{count}개의 인증서가 동기화되었습니다.")
    return redirect('core_cert:certificate_list')

def trigger_cron_renew(request):
    """수동으로 자동 갱신 체크를 트리거합니다."""
    try:
        # 이 작업은 시간이 걸릴 수 있으므로 subprocess로 실행
        subprocess.Popen(['python3', '/app/manage.py', 'cron_renew'])
        messages.success(request, "자동 갱신 체크 프로세스가 백그라운드에서 시작되었습니다. 잠시 후 결과가 반영됩니다.")
    except Exception as e:
        messages.error(request, f"프로세스 시작 실패: {str(e)}")
    return redirect('core_cert:certificate_list')

def setup_renewal_hook(request, pk):
    cert = get_object_or_404(Certificate, pk=pk)
    try:
        cmd = [
            'acme.sh', '--home', '/app/acme.sh', '--install-cert', '-d', cert.domain,
            '--reloadcmd', f'python3 /app/manage.py deploy_domain {cert.domain}'
        ]
        if '_ecc' in cert.cert_path: cmd.append('--ecc')
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            messages.success(request, f"{cert.domain}에 대한 자동 갱신 배포 훅이 설정되었습니다.")
        else:
            messages.error(request, f"훅 설정 실패: {result.stderr}")
    except Exception as e:
        messages.error(request, f"실행 중 오류 발생: {str(e)}")
        
    return redirect('core_cert:certificate_list')

class CertificateListView(ListView):
    model = Certificate
    template_name = 'core_cert/certificate_list.html'
    context_object_name = 'certs'

class CertificateCreateView(CreateView):
    model = Certificate
    form_class = CertificateForm
    template_name = 'core_cert/certificate_form.html'
    success_url = reverse_lazy('core_cert:certificate_list')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        acme_path = '/app/acme.sh'
        dirs = []
        if os.path.exists(acme_path):
            for item in os.listdir(acme_path):
                full_path = os.path.join(acme_path, item)
                if os.path.isdir(full_path) and not item.startswith('.') and item not in ['deploy', 'dnsapi', 'notify', 'ca']:
                    dirs.append({'name': item, 'path': full_path})
        context['acme_dirs'] = dirs
        return context

    def form_valid(self, form):
        instance = form.save(commit=False)
        update_certificate_info(instance)
        instance.save()
        return super().form_valid(form)

class CertificateUpdateView(UpdateView):
    model = Certificate
    form_class = CertificateForm
    template_name = 'core_cert/certificate_form.html'
    success_url = reverse_lazy('core_cert:certificate_list')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['scripts'] = DeployScript.objects.filter(certificate=self.object)
        return context

    def form_valid(self, form):
        instance = form.save(commit=False)
        update_certificate_info(instance)
        instance.save()
        return super().form_valid(form)

# --- Server Management ---

class ServerListView(ListView):
    model = TargetServer
    template_name = 'core_cert/server_list.html'
    context_object_name = 'servers'

class ServerCreateView(CreateView):
    model = TargetServer
    form_class = TargetServerForm
    template_name = 'core_cert/server_form.html'
    success_url = reverse_lazy('core_cert:server_list')

class ServerUpdateView(UpdateView):
    model = TargetServer
    form_class = TargetServerForm
    template_name = 'core_cert/server_form.html'
    success_url = reverse_lazy('core_cert:server_list')

def server_delete(request, pk):
    server = get_object_or_404(TargetServer, pk=pk)
    if request.method == 'POST':
        server.delete()
        messages.success(request, f"서버 '{server.name}'가 삭제되었습니다.")
        return redirect('core_cert:server_list')
    return render(request, 'core_cert/confirm_delete.html', {
        'object': server,
        'title': '서버 삭제',
        'cancel_url': reverse_lazy('core_cert:server_list')
    })

def server_ssh_setup(request, pk):
    server = get_object_or_404(TargetServer, pk=pk)
    return render(request, 'core_cert/server_ssh_setup.html', {'server': server})

def test_ssh_connection(request, pk):
    server = get_object_or_404(TargetServer, pk=pk)
    
    # Ensure keys exist
    ssh_manager.ensure_ssh_keys()
    
    try:
        # Try connecting with both ED25519 and RSA keys
        # We explicitly allow ssh-rsa for legacy servers
        cmd = [
            'ssh', '-v', '-i', ssh_manager.ED25519_KEY_PATH,
            '-i', ssh_manager.RSA_KEY_PATH,
            '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=5',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa',
            '-o', 'HostKeyAlgorithms=+ssh-rsa',
            '-p', str(server.ssh_port),
            f"{server.ssh_user}@{server.ip_address}",
            'echo success'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and 'success' in result.stdout:
            server.ssh_status = 'success'
            messages.success(request, f"{server.name} 연결 테스트 성공!")
        else:
            server.ssh_status = 'failure'
            # Include detailed error from stderr
            detailed_error = result.stderr.strip() or result.stdout.strip() or "알 수 없는 이유로 연결이 거부되었습니다."
            messages.error(request, f"{server.name} 연결 테스트 실패: {detailed_error}")
            
    except subprocess.TimeoutExpired:
        server.ssh_status = 'failure'
        messages.error(request, f"{server.name} 연결 테스트 시간 초과 (10초)")
    except Exception as e:
        server.ssh_status = 'failure'
        messages.error(request, f"테스트 중 오류 발생: {str(e)}")
        
    server.last_tested = timezone.now()
    server.save()
    return redirect('core_cert:server_list')

# --- SSH Key Management ---

def ssh_key_manage(request):
    public_keys = ssh_manager.ensure_ssh_keys()
    if request.method == 'POST':
        if 'regenerate' in request.POST:
            public_keys = ssh_manager.regenerate_keys()
            messages.success(request, "SSH 키가 성공적으로 재생성되었습니다 (RSA 및 ED25519).")
            return redirect('core_cert:ssh_key_manage')
        elif 'save_manual' in request.POST:
            private_key_content = request.POST.get('private_key', '')
            public_key_content = request.POST.get('public_key', '')
            if 'private_key_file' in request.FILES:
                private_key_content = request.FILES['private_key_file'].read().decode('utf-8')
            if 'public_key_file' in request.FILES:
                public_key_content = request.FILES['public_key_file'].read().decode('utf-8')
            if private_key_content:
                ssh_manager.save_ssh_key(private_key_content, public_key_content)
                messages.success(request, "SSH 키가 수동으로 업데이트되었습니다.")
                return redirect('core_cert:ssh_key_manage')
            else:
                messages.error(request, "비공개키 내용은 필수입니다.")
    return render(request, 'core_cert/ssh_key_manage.html', {'public_keys': public_keys})

# --- Deployment Script Management ---

DeploymentTargetFormSet = inlineformset_factory(
    DeployScript, DeploymentTarget, form=DeploymentTargetForm, extra=0, can_delete=True
)
FileMappingFormSet = inlineformset_factory(
    DeploymentTarget, FileMapping, form=FileMappingForm, extra=0, can_delete=True
)

class ScriptListView(ListView):
    model = DeployScript
    template_name = 'core_cert/script_list.html'
    context_object_name = 'scripts'

class ScriptCreateView(CreateView):
    model = DeployScript
    form_class = DeployScriptForm
    template_name = 'core_cert/script_form.html'
    success_url = reverse_lazy('core_cert:script_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.POST:
            formset = DeploymentTargetFormSet(self.request.POST, instance=self.object, prefix='deployment_targets')
        else:
            formset = DeploymentTargetFormSet(instance=self.object, prefix='deployment_targets')
        
        context['formset'] = formset
        context['servers'] = TargetServer.objects.all()
        
        mapping_formsets = []
        for i, form in enumerate(formset):
            prefix = f'mappings-{i}'
            if self.request.POST:
                m_fs = FileMappingFormSet(self.request.POST, instance=form.instance, prefix=prefix)
            else:
                m_fs = FileMappingFormSet(instance=form.instance, prefix=prefix)
            mapping_formsets.append(m_fs)
            
        context['formset_mappings'] = list(zip(formset, mapping_formsets))
        return context

    def form_valid(self, form):
        context = self.get_context_data()
        formset = context['formset']
        formset_mappings = context['formset_mappings']
        
        if not form.is_valid() or not formset.is_valid():
            return self.render_to_response(self.get_context_data(form=form))

        # Validate all mapping formsets
        for _, m_fs in formset_mappings:
            if not m_fs.is_valid():
                return self.render_to_response(self.get_context_data(form=form))

        # Save main object
        self.object = form.save()
        formset.instance = self.object
        
        # Save targets and capture the saved instances
        targets = formset.save()
        
        # Re-map mappings to saved target instances
        # formset_mappings was [(target_form, mapping_formset), ...]
        for target_form, m_fs in formset_mappings:
            if target_form.cleaned_data.get('DELETE'):
                continue
            
            # The target_form.instance now has a PK after formset.save()
            if target_form.instance.pk:
                m_fs.instance = target_form.instance
                # Re-bind POST data to the formset with the new instance PK
                # This ensures the foreign key is correctly set during m_fs.save()
                m_fs.save()

        return redirect('core_cert:script_list')

class ScriptUpdateView(UpdateView):
    model = DeployScript
    form_class = DeployScriptForm
    template_name = 'core_cert/script_form.html'
    success_url = reverse_lazy('core_cert:script_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.POST:
            formset = DeploymentTargetFormSet(self.request.POST, instance=self.object, prefix='deployment_targets')
        else:
            formset = DeploymentTargetFormSet(instance=self.object, prefix='deployment_targets')
        
        context['formset'] = formset
        context['servers'] = TargetServer.objects.all()
        
        mapping_formsets = []
        for i, form in enumerate(formset):
            prefix = f'mappings-{i}'
            if self.request.POST:
                m_fs = FileMappingFormSet(self.request.POST, instance=form.instance, prefix=prefix)
            else:
                m_fs = FileMappingFormSet(instance=form.instance, prefix=prefix)
            mapping_formsets.append(m_fs)
            
        context['formset_mappings'] = list(zip(formset, mapping_formsets))
        return context

    def form_valid(self, form):
        context = self.get_context_data()
        formset = context['formset']
        formset_mappings = context['formset_mappings']
        
        if not form.is_valid() or not formset.is_valid():
            return self.render_to_response(self.get_context_data(form=form))

        # Validate all mapping formsets
        for _, m_fs in formset_mappings:
            if not m_fs.is_valid():
                return self.render_to_response(self.get_context_data(form=form))

        # Save main object
        self.object = form.save()
        formset.instance = self.object
        
        # Save targets and capture the saved instances
        targets = formset.save()
        
        # Re-map mappings to saved target instances
        # formset_mappings was [(target_form, mapping_formset), ...]
        for target_form, m_fs in formset_mappings:
            if target_form.cleaned_data.get('DELETE'):
                continue
            
            # The target_form.instance now has a PK after formset.save()
            if target_form.instance.pk:
                m_fs.instance = target_form.instance
                # Re-bind POST data to the formset with the new instance PK
                # This ensures the foreign key is correctly set during m_fs.save()
                m_fs.save()

        return redirect('core_cert:script_list')

# --- Dashboard & Action ---

from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta

def dashboard(request):
    now = timezone.now()
    thirty_days_later = now + timedelta(days=30)
    
    # 인증서 통계
    certs = Certificate.objects.all()
    expiring_soon = certs.filter(expiry_date__lte=thirty_days_later, expiry_date__gt=now).count()
    expired = certs.filter(expiry_date__lte=now).count()
    
    # 서버 통계
    servers = TargetServer.objects.all()
    server_fail_count = servers.filter(ssh_status='failure').count()
    
    # 배포 통계
    recent_logs = DeploymentLog.objects.order_by('-started_at')[:10]
    deploy_fail_count = DeploymentLog.objects.filter(
        started_at__gte=now - timedelta(days=7),
        status='failure'
    ).count()

    return render(request, 'core_cert/dashboard.html', {
        'certs_count': certs.count(),
        'expiring_soon': expiring_soon,
        'expired_count': expired,
        'servers_count': servers.count(),
        'server_fail_count': server_fail_count,
        'scripts': DeployScript.objects.all(),
        'recent_logs': recent_logs,
        'deploy_fail_count': deploy_fail_count,
    })

def script_detail(request, pk):
    script = get_object_or_404(DeployScript, pk=pk)
    return render(request, 'core_cert/script_detail.html', {
        'script': script,
        'logs': DeploymentLog.objects.filter(script=script).order_by('-started_at')
    })

def certificate_action_view(request, pk, action, title):
    cert = get_object_or_404(Certificate, pk=pk)
    return render(request, 'core_cert/certificate_action.html', {'cert': cert, 'action': action, 'title': title})

def certificate_issue(request, pk): return certificate_action_view(request, pk, 'issue', '인증서 신규 발급')
def certificate_test_issue(request, pk): return certificate_action_view(request, pk, 'test_issue', '인증서 테스트 발급 (스테이징)')
def certificate_renew(request, pk): return certificate_action_view(request, pk, 'renew', '인증서 갱신')

def certificate_delete(request, pk):
    cert = get_object_or_404(Certificate, pk=pk)
    if request.method == 'POST':
        cert.delete()
        messages.success(request, f"인증서 '{cert.domain}'가 삭제되었습니다.")
        return redirect('core_cert:certificate_list')
    return render(request, 'core_cert/confirm_delete.html', {
        'object': cert,
        'title': '인증서 삭제',
        'cancel_url': reverse_lazy('core_cert:certificate_list')
    })

def script_delete(request, pk):
    script = get_object_or_404(DeployScript, pk=pk)
    if request.method == 'POST':
        script.delete()
        messages.success(request, f"배포 스크립트 '{script.name}'가 삭제되었습니다.")
        return redirect('core_cert:script_list')
    return render(request, 'core_cert/confirm_delete.html', {
        'object': script,
        'title': '배포 스크립트 삭제',
        'cancel_url': reverse_lazy('core_cert:script_list')
    })

from django.http import JsonResponse
from urllib.parse import urlparse

def get_cname_info(request, pk):
    """acme.sh 설정 파일에서 acme-dns CNAME 정보를 추출하여 반환합니다."""
    cert = get_object_or_404(Certificate, pk=pk)
    base_domain = cert.domain.replace('*.', '')
    conf_path = os.path.join('/app/acme.sh', f"{base_domain}_ecc", f"{base_domain}.conf")
    
    if not os.path.exists(conf_path):
        return JsonResponse({'error': '아직 인증서 발급 시도가 없거나 설정 파일이 생성되지 않았습니다.'}, status=404)
    
    subdomain = None
    with open(conf_path, 'r') as f:
        for line in f:
            if 'ACMEDNS_SUBDOMAIN' in line:
                subdomain = line.split('=', 1)[1].strip().strip("'").strip('"')
                break
    
    if not subdomain:
        return JsonResponse({'error': '설정 파일에 acme-dns 정보가 없습니다.'}, status=404)
    
    # CNAME 전용 도메인 설정 확인 (없으면 '.도메인'으로 표시)
    dns_host = GlobalSetting.get_value('ACMEDNS_CNAME_DOMAIN')
    if not dns_host:
        dns_host = "(acme-dns 도메인)"
    
    return JsonResponse({
        'domain': f'_acme-challenge.{base_domain}',
        'cname_target': f'{subdomain}.{dns_host}'
    })

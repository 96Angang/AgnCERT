import os
from django import forms
from django.utils.translation import gettext_lazy as _
from .models import Certificate, DeployScript

class CertificateForm(forms.ModelForm):
    CA_CHOICES = [
        ('letsencrypt', "Let's Encrypt"),
        ('zerossl', 'ZeroSSL'),
        ('buypass', 'Buypass'),
        ('google', 'Google Trust Services (GTS)'),
        ('letsencrypt_test', "Let's Encrypt (Staging/Test)"),
    ]

    DNS_PROVIDER_CHOICES = [
        ('dns_acmedns', _('acme-dns (Fixed)')),
    ]

    KEY_TYPE_CHOICES = [
        ('ec-256', _('EC 256 (ECDSA, Recommended)')),
        ('rsa2048', 'RSA 2048'),
        ('rsa4096', 'RSA 4096'),
    ]

    CERT_TYPE_CHOICES = [
        ('auto', _('Automatic (acme.sh / CA Server)')),
        ('manual', _('Manual (Upload ZIP)')),
    ]

    cert_type = forms.ChoiceField(choices=CERT_TYPE_CHOICES, initial='auto', widget=forms.RadioSelect(attrs={'class': 'cert-type-radio'}))
    ca_server = forms.ChoiceField(choices=CA_CHOICES, initial='letsencrypt', widget=forms.Select(attrs={'class': 'form-input'}))
    dns_provider = forms.ChoiceField(choices=DNS_PROVIDER_CHOICES, initial='dns_acmedns', widget=forms.Select(attrs={'class': 'form-input'}))
    key_type = forms.ChoiceField(choices=KEY_TYPE_CHOICES, initial='ec-256', widget=forms.Select(attrs={'class': 'form-input'}))
    upload_zip = forms.FileField(required=False, widget=forms.ClearableFileInput(attrs={'class': 'form-input', 'accept': '.zip'}),
                                 label=_("Certificate ZIP file"),
                                 help_text=_("Upload a ZIP containing the certificate, key and fullchain files."))

    class Meta:
        model = Certificate
        fields = ['name', 'domain', 'cert_path', 'is_wildcard', 'cert_type', 'ca_server', 'key_type', 'dns_provider', 'expiry_date', 'status']
        widgets = {
            'name': forms.TextInput(attrs={
                'placeholder': _('e.g., example.com (Let\'s Encrypt)'),
                'class': 'form-input',
            }),
            'domain': forms.TextInput(attrs={
                'placeholder': _('e.g., example.com or *.example.com'),
                'class': 'form-input',
            }),
            'cert_path': forms.TextInput(attrs={
                'placeholder': _('Automatically suggested on domain input...'),
                'class': 'form-input',
            }),
            'is_wildcard': forms.CheckboxInput(attrs={
                'class': 'form-checkbox',
            }),
            'expiry_date': forms.DateTimeInput(attrs={
                'type': 'datetime-local', 
                'readonly': 'readonly', 
                'class': 'form-input-readonly'
            }),
            'status': forms.TextInput(attrs={
                'readonly': 'readonly', 
                'class': 'form-input-readonly'
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['expiry_date'].required = False
        self.fields['status'].required = False
        self.fields['is_wildcard'].required = False
        self.fields['dns_provider'].required = False
        self.fields['name'].required = False
        self.fields['name'].label = _("Title")
        self.fields['cert_type'].label = _("Issuance Method")
        self.fields['ca_server'].label = _("CA Server")
        self.fields['key_type'].label = _("Key Type")
        self.fields['cert_path'].required = False
        self.fields['cert_path'].help_text = _("Certificate path in acme.sh. (Suggested automatically)")

        if not self.instance.pk:
            self.fields['expiry_date'].widget.attrs['placeholder'] = _('Calculated on issuance.')
            self.fields['status'].widget.attrs['placeholder'] = _('Calculated on issuance.')
            self.initial['status'] = 'pending'

    def clean(self):
        cleaned_data = super().clean()
        cert_type = cleaned_data.get('cert_type')
        upload_zip = cleaned_data.get('upload_zip')
        domain = cleaned_data.get('domain')

        if cert_type == 'manual':
            # 수동: 신규 등록 시 ZIP 필수
            if not self.instance.pk and not upload_zip:
                self.add_error('upload_zip', _("A ZIP file is required for manual certificates."))
            if upload_zip and not upload_zip.name.lower().endswith('.zip'):
                self.add_error('upload_zip', _("Only ZIP files are allowed."))
            # 수동 인증서의 경로는 manual 폴더로 고정
            if domain and not cleaned_data.get('cert_path'):
                base_domain = domain.replace('*.', '')
                cleaned_data['cert_path'] = f"/app/acme.sh/manual/{base_domain}"
        else:
            # 자동: 경로 미입력 시 도메인 기반 기본 경로 생성
            if domain and not cleaned_data.get('cert_path'):
                base_domain = domain.replace('*.', '')
                key_type = cleaned_data.get('key_type', 'ec-256')
                suffix = f"{base_domain}_ecc" if key_type == 'ec-256' else base_domain
                ca = cleaned_data.get('ca_server')
                if ca == 'zerossl':
                    cleaned_data['cert_path'] = f"/app/acme.sh/ZeroSSL/{suffix}"
                elif ca == 'google':
                    cleaned_data['cert_path'] = f"/app/acme.sh/Google/{suffix}"
                else:
                    cleaned_data['cert_path'] = f"/app/acme.sh/{suffix}"
        return cleaned_data

DEFAULT_SCRIPT_CONTENT = """#!/bin/bash

# [AgnCERT] 배포 스크립트 템플릿
# 도메인: {{ DOMAIN }}
# 설명: 이 스크립트는 인증서를 원격 서버로 전송하고 서비스를 재시작합니다.

# --- 설정 변수 ---
CERT_DOMAIN="{{ DOMAIN }}"
CERT_PATH="{{ CERT_PATH }}"
SSH_KEY="/app/.ssh/id_rsa"

# --- 대상 서버 정보 (서버 관리 메뉴 참고) ---
# 예시:
# TARGET_USER="root"
# TARGET_IP="1.2.3.4"
# TARGET_DIR="/etc/nginx/ssl"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log ">>> 배포 시작: $CERT_DOMAIN"

# --- 유효성 검사 ---
if [ ! -d "$CERT_PATH" ]; then
    log "오류: 인증서 경로를 찾을 수 없습니다: $CERT_PATH"
    exit 1
fi

# --- 배포 로직 (예시) ---
# scp -i "$SSH_KEY" "$CERT_PATH"/fullchain.* "$TARGET_USER@$TARGET_IP:$TARGET_DIR/"
# ssh -i "$SSH_KEY" "$TARGET_USER@$TARGET_IP" "systemctl reload nginx"

log ">>> 배포 완료!"
exit 0
"""

from .models import Certificate, DeployScript, TargetServer, DeploymentTarget, FileMapping

class TargetServerForm(forms.ModelForm):
    class Meta:
        model = TargetServer
        fields = ['name', 'ip_address', 'ssh_port', 'ssh_user', 'os_type', 'web_server_type', 'path_type', 'custom_path', 'ssl_config_path']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-input', 'placeholder': _('Server Name (e.g., Production Nginx)')}),
            'ip_address': forms.TextInput(attrs={'class': 'form-input', 'placeholder': '1.2.3.4'}),
            'ssh_port': forms.NumberInput(attrs={'class': 'form-input'}),
            'ssh_user': forms.TextInput(attrs={'class': 'form-input'}),
            'os_type': forms.Select(attrs={'class': 'form-input'}),
            'web_server_type': forms.Select(attrs={'class': 'form-input'}),
            'path_type': forms.Select(attrs={'class': 'form-input'}),
            'custom_path': forms.TextInput(attrs={'class': 'form-input', 'placeholder': _('e.g., /etc/nginx/ssl')}),
            'ssl_config_path': forms.TextInput(attrs={'class': 'form-input', 'placeholder': _('e.g., /etc/httpd/conf.d/ssl.conf')}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['custom_path'].required = False
        self.fields['ssl_config_path'].required = False

    # OS별 허용 웹서버 (안전장치): Windows=IIS/없음, Linux=Nginx/Apache/없음
    ALLOWED_WEB_BY_OS = {
        'windows': ['none', 'iis'],
        'linux': ['none', 'nginx', 'apache'],
    }

    def clean(self):
        cleaned = super().clean()
        os_type = cleaned.get('os_type')
        web = cleaned.get('web_server_type')
        allowed = self.ALLOWED_WEB_BY_OS.get(os_type)
        if allowed and web and web not in allowed:
            self.add_error('web_server_type', _("This web server type is not valid for the selected OS."))
        return cleaned

class DeployScriptForm(forms.ModelForm):
    class Meta:
        model = DeployScript
        fields = ['certificate', 'name']
        widgets = {
            'certificate': forms.Select(attrs={'class': 'form-input'}),
            'name': forms.TextInput(attrs={'class': 'form-input'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class DeploymentTargetForm(forms.ModelForm):
    # 선택된 도커 컨테이너 이름 목록을 JSON 문자열로 받는 hidden 필드.
    # 템플릿의 체크박스 선택을 JS가 직렬화해 채운다.
    restart_containers_json = forms.CharField(required=False, widget=forms.HiddenInput(attrs={'class': 'restart-containers-input'}))

    class Meta:
        model = DeploymentTarget
        fields = ['server', 'remote_path', 'reload_command', 'prepare_dir', 'transfer_files', 'reload_service', 'include_all_bindings']
        widgets = {
            'server': forms.Select(attrs={'class': 'form-input server-select'}),
            'remote_path': forms.TextInput(attrs={'class': 'form-input', 'placeholder': '/etc/nginx/ssl'}),
            'reload_command': forms.TextInput(attrs={'class': 'form-input', 'placeholder': _('e.g., systemctl reload nginx or custom script')}),
            'prepare_dir': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
            'transfer_files': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
            'reload_service': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
            'include_all_bindings': forms.CheckboxInput(attrs={'class': 'form-checkbox'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 기존 인스턴스의 컨테이너 목록을 JSON 문자열로 초기화
        import json
        if self.instance and self.instance.pk:
            self.fields['restart_containers_json'].initial = json.dumps(self.instance.restart_containers or [])

    def clean(self):
        import json
        cleaned = super().clean()
        raw = (cleaned.get('restart_containers_json') or '').strip()
        names = []
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    names = [str(x).strip() for x in parsed if str(x).strip()]
            except (ValueError, TypeError):
                names = []
        self.instance.restart_containers = names
        return cleaned

class FileMappingForm(forms.ModelForm):
    class Meta:
        model = FileMapping
        fields = ['file_type', 'custom_filename', 'custom_path']
        widgets = {
            'file_type': forms.Select(attrs={'class': 'form-input', 'style': 'font-size: 0.85rem;'}),
            'custom_filename': forms.TextInput(attrs={'class': 'form-input', 'placeholder': _('Rename file (Optional)'), 'style': 'font-size: 0.85rem;'}),
            'custom_path': forms.TextInput(attrs={'class': 'form-input', 'placeholder': _('Specific path (Optional)'), 'style': 'font-size: 0.85rem;'}),
        }

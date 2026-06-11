from django.db import models
from django.utils.translation import gettext_lazy as _

class Certificate(models.Model):
    name = models.CharField(max_length=200, blank=True, verbose_name=_("Name"))
    domain = models.CharField(max_length=255)
    cert_path = models.CharField(max_length=512)
    serial = models.CharField(max_length=128, blank=True, null=True, help_text=_("Unique certificate serial number"))
    expiry_date = models.DateTimeField(null=True, blank=True)
    last_renewed = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=50, default='valid')
    is_wildcard = models.BooleanField(default=False, help_text=_("Whether it is a wildcard certificate (*.domain.com)"))
    allowed_domains = models.TextField(blank=True, help_text=_("All domains included in the certificate (SANs)"))
    
    CERT_TYPE_CHOICES = [
        ('auto', _('Automatic (acme.sh / CA Server)')),
        ('manual', _('Manual (Upload files)')),
    ]
    cert_type = models.CharField(max_length=10, choices=CERT_TYPE_CHOICES, default='auto', help_text=_("Issuance method: automatic via acme.sh or manual upload"))

    # acme.sh specific fields
    is_acme = models.BooleanField(default=True, help_text=_("Whether the certificate is managed by acme.sh"))
    ca_server = models.CharField(max_length=100, default='letsencrypt', help_text=_("CA Server (e.g., letsencrypt, zerossl)"))
    dns_provider = models.CharField(max_length=50, blank=True, help_text=_("e.g., dns_cf, dns_aws"))
    key_type = models.CharField(max_length=20, default='ec-256', choices=[
        ('ec-256', 'EC 256 (ECDSA)'),
        ('rsa2048', 'RSA 2048'),
        ('rsa4096', 'RSA 4096'),
    ], help_text=_("Key type and length"))

    def __str__(self):
        return self.name if self.name else self.domain

    @property
    def renewal_date(self):
        """만료일 기준 갱신 예정일을 계산합니다."""
        if not self.expiry_date:
            return None
        from datetime import timedelta
        # 빈 문자열로 저장된 경우에도 기본값(30)으로 폴백한다.
        try:
            days = int(GlobalSetting.get_value('RENEWAL_DAYS_BEFORE', '30') or '30')
        except (TypeError, ValueError):
            days = 30
        return self.expiry_date - timedelta(days=days)

    def get_source_file(self, file_type):
        """인증서 폴더 내에서 실제 파일 시스템을 조사하여 가장 적절한 소스 파일을 찾습니다."""
        import os
        if not self.cert_path or not os.path.exists(self.cert_path):
            return None
        
        base_domain = self.domain.replace('*.', '')
        
        # 1. Private Key
        if file_type == 'key':
            for f_name in [f"{base_domain}.key", f"{base_domain}.pem", "key.pem", "privkey.key", "key.key"]:
                f = os.path.join(self.cert_path, f_name)
                if os.path.exists(f): return f_name
                
        # 2. Certificate (Only)
        elif file_type == 'cert':
            for f_name in [f"{base_domain}.cer", f"{base_domain}.pem", "cert.pem", "cert.cer"]:
                f = os.path.join(self.cert_path, f_name)
                if os.path.exists(f): return f_name
                
        # 3. Fullchain
        elif file_type == 'fullchain':
            for f_name in [f"{base_domain}_fullchain.cer", f"{base_domain}.fullchain.cer", "fullchain.cer", "fullchain.pem"]:
                f = os.path.join(self.cert_path, f_name)
                if os.path.exists(f): return f_name
                
        # 4. PFX
        elif file_type == 'pfx':
            for f_name in [f"{base_domain}.pfx", "cert.pfx"]:
                f = os.path.join(self.cert_path, f_name)
                if os.path.exists(f): return f_name

        # 5. Root CA chain (leaf 제외 CA 체인 번들, 루트 포함)
        elif file_type == 'rootca':
            for f_name in [f"{base_domain}_RootCA.pem", "ca.cer", "ca.pem"]:
                f = os.path.join(self.cert_path, f_name)
                if os.path.exists(f): return f_name

        # 6. Intermediate chain (Apache SSLCertificateChainFile용 — leaf·루트 제외 중간 CA)
        elif file_type == 'chain':
            for f_name in [f"{base_domain}_chain.cer", f"{base_domain}_chain.pem", "ca.cer", "chain.pem"]:
                f = os.path.join(self.cert_path, f_name)
                if os.path.exists(f): return f_name

        # 6-1. 구형 기기용 cross-sign 변형 체인 (ZeroSSL): _chain_AAA.cer / _chain_USERTRUST.cer
        elif file_type == 'chain_aaa':
            f_name = f"{base_domain}_chain_AAA.cer"
            if os.path.exists(os.path.join(self.cert_path, f_name)): return f_name
        elif file_type == 'chain_usertrust':
            f_name = f"{base_domain}_chain_USERTRUST.cer"
            if os.path.exists(os.path.join(self.cert_path, f_name)): return f_name

        return None

class TargetServer(models.Model):
    name = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    ssh_port = models.IntegerField(default=22)
    ssh_user = models.CharField(max_length=50, default='root')
    os_type = models.CharField(max_length=10, choices=[('linux', 'Linux'), ('windows', 'Windows')], default='linux')
    ssh_status = models.CharField(max_length=20, default='pending', choices=[
        ('pending', _('Pending')),
        ('success', _('Connected')),
        ('failure', _('Failed'))
    ])
    
    WEB_SERVER_CHOICES = [
        ('none', _('None')),
        ('nginx', 'Nginx'),
        ('apache', 'Apache (httpd)'),
        ('iis', 'IIS (Windows)'),
    ]
    web_server_type = models.CharField(max_length=20, choices=WEB_SERVER_CHOICES, default='none')
    
    PATH_TYPE_CHOICES = [
        ('default', _('Default Path')),
        ('custom', _('Custom Path')),
    ]
    path_type = models.CharField(max_length=20, choices=PATH_TYPE_CHOICES, default='default')
    custom_path = models.TextField(blank=True, help_text=_("Input if custom path is selected (e.g., /etc/nginx/ssl)"))
    ssl_config_path = models.CharField(max_length=512, blank=True, help_text=_("SSL config file path (e.g., /etc/httpd/conf.d/ssl.conf)"))

    last_tested = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.ip_address})"

class TargetServerSite(models.Model):
    server = models.ForeignKey(TargetServer, on_delete=models.CASCADE, related_name='sites')
    domain = models.CharField(max_length=255)
    port = models.IntegerField(default=443, help_text=_("Service port (usually 443)"))
    last_discovered = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('server', 'domain', 'port')

    def __str__(self):
        return f"{self.domain}:{self.port} on {self.server.name}"

class DeployScript(models.Model):
    certificate = models.ForeignKey(Certificate, on_delete=models.CASCADE, related_name='deploy_scripts')
    name = models.CharField(max_length=255)
    last_executed = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.name

class DeploymentTarget(models.Model):
    script = models.ForeignKey(DeployScript, on_delete=models.CASCADE, related_name='deployment_targets')
    server = models.ForeignKey(TargetServer, on_delete=models.CASCADE, related_name='deployment_targets')
    remote_path = models.TextField(help_text=_("Remote server path where the certificate will be stored"))
    reload_command = models.TextField(blank=True, help_text=_("e.g., systemctl reload nginx"))
    
    prepare_dir = models.BooleanField(default=True, help_text=_("Create target directory"))
    transfer_files = models.BooleanField(default=True, help_text=_("Transfer certificate files"))
    reload_service = models.BooleanField(default=True, help_text=_("Run post-processing script (EXEC)"))
    include_all_bindings = models.BooleanField(default=False, help_text=_("Also update the certificate on the 443 binding with an empty host name (Windows only)"))
    restart_containers = models.JSONField(default=list, blank=True, help_text=_("Names of Docker containers to restart after deployment (Linux & Windows)"))

    def __str__(self):
        return f"{self.server.name} ({self.remote_path})"

class FileMapping(models.Model):
    deployment_target = models.ForeignKey(DeploymentTarget, on_delete=models.CASCADE, related_name='file_mappings')
    FILE_TYPE_CHOICES = [
        ('fullchain', _('Fullchain (fullchain.cer/pem)')),
        ('key', _('Private Key (.key/pem)')),
        ('cert', _('Certificate (.cer/pem)')),
        ('chain', _('Intermediate chain (domain_chain.cer)')),
        ('chain_aaa', _('Intermediate chain — AAA cross-sign, legacy (ZeroSSL)')),
        ('chain_usertrust', _('Intermediate chain — USERTrust cross-sign, legacy (ZeroSSL)')),
        ('pfx', _('PFX (cert.pfx)')),
        ('rootca', _('Root CA chain (domain_RootCA.pem)')),
    ]
    file_type = models.CharField(max_length=20, choices=FILE_TYPE_CHOICES)
    custom_filename = models.CharField(max_length=255, blank=True, help_text=_("If empty, default filename will be used."))
    custom_path = models.CharField(max_length=512, blank=True, help_text=_("If set, this file is sent to this specific path instead of the target's common path. The directory is created automatically. (Linux & Windows)"))

    def __str__(self):
        return f"{self.file_type} -> {self.custom_path or 'default-path'}/{self.custom_filename or 'default'}"

class DeploymentLog(models.Model):
    script = models.ForeignKey(DeployScript, on_delete=models.CASCADE)
    status = models.CharField(max_length=20) # success, failure, running, partial_success
    is_resolved = models.BooleanField(default=False, help_text="실패 시 해결 여부")
    log_output = models.TextField(blank=True, help_text="전체 요약 로그")
    details = models.JSONField(default=dict, blank=True, help_text="서버별 상세 결과")
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.script.name} at {self.started_at}"

class GlobalSetting(models.Model):
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField(blank=True)
    description = models.CharField(max_length=255, blank=True)

    def __cl_str__(self):
        return self.key

    @classmethod
    def get_value(cls, key, default=""):
        try:
            return cls.objects.get(key=key).value
        except cls.DoesNotExist:
            return default

    @classmethod
    def set_value(cls, key, value, description=""):
        obj, created = cls.objects.update_or_create(
            key=key,
            defaults={'value': value, 'description': description}
        )
        return obj

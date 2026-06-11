from django.contrib import admin
from .models import Certificate, TargetServer, DeployScript, DeploymentLog

@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ('domain', 'expiry_date', 'last_renewed', 'status')
    search_fields = ('domain',)

@admin.register(TargetServer)
class TargetServerAdmin(admin.ModelAdmin):
    list_display = ('name', 'ip_address', 'ssh_user')
    search_fields = ('name', 'ip_address')

@admin.register(DeployScript)
class DeployScriptAdmin(admin.ModelAdmin):
    list_display = ('name', 'certificate', 'last_executed')
    search_fields = ('name', 'certificate__domain')

@admin.register(DeploymentLog)
class DeploymentLogAdmin(admin.ModelAdmin):
    list_display = ('script', 'status', 'started_at', 'finished_at')
    list_filter = ('status', 'started_at')

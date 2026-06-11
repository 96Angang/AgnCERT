from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

app_name = 'core_cert'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('login/', auth_views.LoginView.as_view(template_name='core_cert/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='core_cert:login'), name='logout'),
    path('settings/', views.global_settings_view, name='settings'),
    path('certificates/', views.CertificateListView.as_view(), name='certificate_list'),
    path('certificates/add/', views.CertificateCreateView.as_view(), name='certificate_add'),
    path('certificates/<int:pk>/edit/', views.CertificateUpdateView.as_view(), name='certificate_edit'),
    path('certificates/<int:pk>/delete/', views.certificate_delete, name='certificate_delete'),
    path('certificates/sync/', views.sync_certificates, name='certificate_sync'),
    path('certificates/cron-renew/', views.trigger_cron_renew, name='cron_renew_trigger'),
    path('certificates/<int:pk>/setup-hook/', views.setup_renewal_hook, name='setup_renewal_hook'),
    path('certificates/<int:pk>/issue/', views.certificate_issue, name='certificate_issue'),
    path('certificates/<int:pk>/test-issue/', views.certificate_test_issue, name='certificate_test_issue'),
    path('certificates/<int:pk>/renew/', views.certificate_renew, name='certificate_renew'),
    path('certificates/<int:pk>/cname-info/', views.get_cname_info, name='get_cname_info'),
    path('certificates/<int:pk>/regenerate-files/', views.regenerate_cert_files, name='regenerate_cert_files'),
    path('certificates/<int:pk>/restore-previous/', views.restore_manual_cert, name='restore_manual_cert'),
    path('settings/save/', views.save_global_settings, name='save_global_settings'),
    
    path('servers/', views.ServerListView.as_view(), name='server_list'),
    path('servers/add/', views.ServerCreateView.as_view(), name='server_add'),
    path('servers/<int:pk>/edit/', views.ServerUpdateView.as_view(), name='server_edit'),
    path('servers/<int:pk>/delete/', views.server_delete, name='server_delete'),
    path('servers/<int:pk>/ssh-setup/', views.server_ssh_setup, name='server_ssh_setup'),
    path('servers/<int:pk>/test-ssh/', views.test_ssh_connection, name='test_ssh_connection'),
    path('servers/<int:pk>/docker-ps/', views.server_docker_ps, name='server_docker_ps'),
    path('servers/<int:pk>/test-sites/', views.test_sites_verification, name='test_sites_verification'),
    path('servers/test-sites-bulk/', views.test_sites_verification_bulk, name='test_sites_verification_bulk'),
    path('servers/bulk-delete/', views.bulk_server_delete, name='bulk_server_delete'),
    path('servers/ssh-keys/', views.ssh_key_manage, name='ssh_key_manage'),

    path('scripts/', views.ScriptListView.as_view(), name='script_list'),
    path('scripts/add/', views.ScriptCreateView.as_view(), name='script_add'),
    path('scripts/<int:pk>/edit/', views.ScriptUpdateView.as_view(), name='script_edit'),
    path('scripts/<int:pk>/delete/', views.script_delete, name='script_delete'),
    path('scripts/<int:pk>/', views.script_detail, name='script_detail'),
    path('logs/<int:pk>/resolve/', views.resolve_log, name='resolve_log'),
    path('logs/<int:pk>/delete/', views.delete_log, name='delete_log'),
    path('logs/bulk-action/', views.bulk_log_action, name='bulk_log_action'),
    path('api/cname/<int:pk>/', views.get_cname_info, name='get_cname_info_api'),
]

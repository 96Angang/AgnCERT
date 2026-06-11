from celery import shared_task
from .models import Certificate
from django.utils import timezone
import subprocess
import os

@shared_task
def certificate_cron_renew_task():
    """모든 인증서의 갱신 필요 여부를 체크하고 자동 발급 및 배포를 수행합니다."""
    from django.core.management import call_command
    print(f"[{timezone.now()}] Starting automatic certificate renewal check...")
    try:
        call_command('cron_renew')
        return "Renewal check completed successfully."
    except Exception as e:
        return f"Error during renewal: {str(e)}"

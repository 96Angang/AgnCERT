import subprocess
import os
import logging
from django.core.management.base import BaseCommand
from core_cert.models import Certificate
from core_cert.views import update_certificate_info

logger = logging.getLogger('core_cert')


def log_certificate_statuses():
    """모든 인증서(자동·수동 포함)의 만료 상태를 django.log 에 한 줄씩 남긴다.
    Telegraf 등 외부 모니터링이 파싱하기 쉽도록 'key=value' 고정 포맷을 사용한다.
    - 정상: logger.info  [CertStatus]
    - 갱신 기준일(RENEWAL_DAYS_BEFORE) 이내 임박: logger.warning  [CertExpiringSoon]
    - 이미 만료: logger.error  [CertExpired]
    수동 인증서는 acme.sh --cron 대상이 아니므로 자동 재배포되지 않는다.
    이 로그가 수동 인증서를 사람이 직접 갱신해야 함을 알리는 유일한 신호다."""
    from django.utils import timezone
    from core_cert.models import GlobalSetting
    try:
        days_before = int(GlobalSetting.get_value('RENEWAL_DAYS_BEFORE', '30'))
    except (TypeError, ValueError):
        days_before = 30
    now = timezone.now()
    for cert in Certificate.objects.all().order_by('domain'):
        expiry = cert.expiry_date
        if expiry:
            days_left = (expiry - now).days
            expiry_str = timezone.localtime(expiry).strftime('%Y-%m-%d %H:%M')
        else:
            days_left = None
            expiry_str = 'unknown'
        fields = (
            f"domain={cert.domain} is_acme={cert.is_acme} ca={cert.ca_server} "
            f"status={cert.status} days_left={days_left} expiry={expiry_str}"
        )
        if expiry is None:
            logger.warning(f"[CertStatusUnknown] {fields} (no expiry date — run sync/issue)")
        elif days_left < 0:
            logger.error(f"[CertExpired] {fields}")
        elif days_left <= days_before:
            note = "" if cert.is_acme else " (MANUAL — renew & redeploy by hand)"
            logger.warning(f"[CertExpiringSoon] {fields}{note}")
        else:
            logger.info(f"[CertStatus] {fields}")


class Command(BaseCommand):
    help = 'Runs acme.sh cron to check and renew certificates'

    def handle(self, *args, **options):
        self.stdout.write("Starting acme.sh renewal check...")
        logger.info("[CronRenew] Starting acme.sh renewal check...")

        from core_cert.models import GlobalSetting
        # 빈 문자열로 저장된 경우에도 기본값(30)으로 폴백한다.
        days = GlobalSetting.get_value('RENEWAL_DAYS_BEFORE', '30') or '30'

        # 1. Run acme.sh cron
        # --days 옵션을 통해 설정된 갱신 기준일(n일 전)을 적용합니다.
        # DNS 슬립을 40초로 통일 (도메인 conf에 저장된 옛 값 무시)
        cmd = ['acme.sh', '--cron', '--home', '/app/acme.sh', '--days', days, '--dnssleep', '40']
        
        env = os.environ.copy()
        env['HTTPS_INSECURE'] = '1'
        
        try:
            # Run the cron command
            # acme.sh cron will automatically trigger reloadcmds for renewed certs
            result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            self.stdout.write(result.stdout)
            if result.stderr:
                self.stderr.write(result.stderr)
            
            self.stdout.write(self.style.SUCCESS("acme.sh cron execution finished."))
            
            # 2. Refresh all certificate info in the database to sync expiry dates
            self.stdout.write("Refreshing certificate info in database...")
            for cert in Certificate.objects.all():
                update_certificate_info(cert)
                cert.save()
            self.stdout.write(self.style.SUCCESS("Database sync complete."))

            # 2.5. 모든 인증서(자동·수동)의 만료 상태를 django.log 에 한 줄씩 기록
            # (Telegraf 등 외부 모니터링용. 수동 인증서는 자동 갱신되지 않으므로 이 로그가 만료 알림 신호다.)
            log_certificate_statuses()

            # 3. Record last run time
            from core_cert.models import GlobalSetting
            from django.utils import timezone
            readable_now = timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M:%S')
            GlobalSetting.set_value('LAST_CRON_RENEWAL', readable_now, '마지막 자동 갱신 체크 일시')
            self.stdout.write(self.style.SUCCESS(f"Last run time recorded: {readable_now}"))
            logger.info(f"[CronRenew] Finished. Last run time recorded: {readable_now}")

        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Error during renewal check: {str(e)}"))
            logger.error(f"[CronRenew] Error during renewal check: {str(e)}")

import time
from django.core.management.base import BaseCommand
from django.utils import timezone
from core_cert.models import GlobalSetting
from django.core.management import call_command

class Command(BaseCommand):
    help = 'Continuous background loop to check and run scheduled renewals'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Starting Python-based background renewal scheduler..."))
        last_run_date = None
        last_target_time = None

        while True:
            try:
                # 1. Get current local time
                now = timezone.localtime(timezone.now())
                current_time_str = now.strftime('%H:%M')
                current_date_str = now.strftime('%Y-%m-%d')

                # 2. Get target time from DB
                # 빈 문자열로 저장된 경우에도 기본값(03:00)으로 폴백한다.
                target_time_str = (GlobalSetting.get_value('RENEWAL_TIME', '03:00') or '03:00').strip() or '03:00'

                # 설정 시간이 바뀌었는지 감지
                if target_time_str != last_target_time:
                    self.stdout.write(f"[{now}] Schedule updated: {last_target_time} -> {target_time_str}")
                    # 시간이 바뀌면 오늘 이미 실행했더라도 다시 실행 기회를 줌
                    if last_target_time is not None:
                        last_run_date = None 
                    last_target_time = target_time_str

                # 3. Check if it's time to run
                if current_time_str == target_time_str:
                    if last_run_date != current_date_str:
                        self.stdout.write(f"[{now}] Time matched ({target_time_str}). Starting renewal check...")
                        call_command('cron_renew')
                        last_run_date = current_date_str
                        self.stdout.write(f"[{now}] Execution finished. Next run tomorrow at {target_time_str}.")
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"Error in scheduler loop: {str(e)}"))

            time.sleep(10)

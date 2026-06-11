import os
from celery import Celery

# Django의 세팅 모듈을 Celery 프로그램의 기본으로 설정합니다.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('AgnCert')

# 여기서 문자열을 사용하는 것은 워커(worker)가 자식 프로세스로 넘겨질 때 
# 객체를 피클링(pickle)하지 않아도 된다는 의미입니다.
# namespace='CELERY'는 모든 셀러리 관련 설정 키가 'CELERY_'로 시작해야 함을 의미합니다.
app.config_from_object('django.conf:settings', namespace='CELERY')

# 등록된 모든 장고 앱 설정에서 task를 불러옵니다.
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')

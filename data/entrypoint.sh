#!/bin/bash

# 에러 발생 시 즉시 중단
set -e

# 작업 디렉토리로 이동 (Dockerfile에서 /app으로 설정됨)
cd /app

# 1. 장고 로그 폴더 생성
mkdir -p logs staticfiles acme.sh

# acme.sh 필수 구성 요소 자동 설치/복사
if [ -d "/root/.acme.sh" ]; then
    if [ ! -f "/app/acme.sh/acme.sh" ] || [ ! -d "/app/acme.sh/dnsapi" ]; then
        echo "Initializing acme.sh in /app/acme.sh from system install..."
        cp -rf /root/.acme.sh/* /app/acme.sh/
        echo "acme.sh initialization complete."
    fi
fi

# 2. MariaDB 부팅 대기 (접속 정보는 환경변수에서 읽음)
echo "Waiting for MariaDB to start..."
until python -c "
import sys, os, pymysql
try:
    pymysql.connect(
        host=os.getenv('DB_HOST', 'mariadb'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME'),
        port=int(os.getenv('DB_PORT', '3306')),
    )
except Exception:
    sys.exit(-1)
" 2>/dev/null; do
    echo "MariaDB is unavailable - sleeping..."
    sleep 2
done
echo "MariaDB is up!"

# 3. 마이그레이션 적용
if [ "${RUN_MAKEMIGRATIONS:-False}" = "True" ]; then
    echo "Generating migrations because RUN_MAKEMIGRATIONS=True..."
    python manage.py makemigrations --noinput
fi
echo "Applying database migrations..."
python manage.py migrate --noinput

# 4. 관리자 계정 생성 (명시적인 환경변수가 있을 때만 수행)
if [ -n "${DJANGO_SUPERUSER_USERNAME:-}" ] && [ -n "${DJANGO_SUPERUSER_EMAIL:-}" ] && [ -n "${DJANGO_SUPERUSER_PASSWORD:-}" ]; then
    echo "Ensuring superuser '${DJANGO_SUPERUSER_USERNAME}' exists..."
    python manage.py shell -c "
import os
from django.contrib.auth import get_user_model
User = get_user_model()
username = os.environ['DJANGO_SUPERUSER_USERNAME']
if not User.objects.filter(username=username).exists():
    User.objects.create_superuser(username, os.environ['DJANGO_SUPERUSER_EMAIL'], os.environ['DJANGO_SUPERUSER_PASSWORD'])
    print(f'Superuser {username} created.')
else:
    print(f'Superuser {username} already exists.')
"
else
    echo "Skipping superuser creation because DJANGO_SUPERUSER_* is not fully configured."
fi

# 4.5. 자동 갱신 태스크 등록 (Daily)
echo "Ensuring daily renewal task is scheduled..."
python manage.py shell -c "
from django_celery_beat.models import PeriodicTask, IntervalSchedule
schedule, _ = IntervalSchedule.objects.get_or_create(every=1, period=IntervalSchedule.DAYS)
PeriodicTask.objects.get_or_create(
    interval=schedule,
    name='certificate-auto-renewal-daily',
    task='core_cert.tasks.certificate_cron_renew_task',
)
print('Renewal task scheduled.')
"

# 5. 번역 파일 컴파일 (있는 경우)
if [ -d "locale" ]; then
    echo "Compiling translation messages..."
    python manage.py compilemessages
fi

# 6. 정적 파일 수집
echo "Collecting static files..."
python manage.py collectstatic --noinput

# 7. Celery Worker/Beat 실행 (백그라운드)
echo "Starting Celery Worker..."
celery -A config worker -l info &

echo "Starting Celery Beat..."
celery -A config beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler &

# 8. 장고 서버 실행
echo "Starting Django server on port ${DJANGO_PORT:-8000} (DEBUG=${DEBUG})..."

if [ "${DEBUG}" = "True" ]; then
    echo "Running in Development mode (runserver)..."
    python manage.py runserver 0.0.0.0:${DJANGO_PORT:-8000}
else
    echo "Running in Production mode (daphne)..."
    daphne -b 0.0.0.0 -p ${DJANGO_PORT:-8000} config.asgi:application
fi

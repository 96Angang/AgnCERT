"""
Django settings for config project.
"""

from pathlib import Path
import os
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')

# MariaDB/MySQL support via PyMySQL
if os.getenv('DB_ENGINE') == 'django.db.backends.mysql':
    import pymysql
    pymysql.install_as_MySQLdb()

def get_secret_key():
    secret_key = os.getenv('SECRET_KEY')
    if secret_key:
        return secret_key
    
    secret_file = BASE_DIR / '.secret_key'
    if secret_file.exists():
        return secret_file.read_text().strip()
    
    # Generate a new secret key and save it to a file
    from django.core.management.utils import get_random_secret_key
    new_key = get_random_secret_key()
    secret_file.write_text(new_key)
    return new_key

SECRET_KEY = get_secret_key()
DEBUG = os.getenv('DEBUG', 'True') == 'True'
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'daphne',  # Channels/WebSocket 지원을 위해 가장 위에 위치
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'channels',
    'django_celery_beat',
    'core_cert',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware', # i18n 지원을 위한 언어 미들웨어 추가
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'config.middleware.AdminIPRestrictionMiddleware',
    'core_cert.middleware.login_required.LoginRequiredMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.i18n',
                'core_cert.context_processors.global_settings',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'

if os.getenv('DB_ENGINE'):
    engine = os.getenv('DB_ENGINE')
    DATABASES = {
        'default': {
            'ENGINE': engine,
            'NAME': os.getenv('DB_NAME'),
            'USER': os.getenv('DB_USER', ''),
            'PASSWORD': os.getenv('DB_PASSWORD', ''),
            'HOST': os.getenv('DB_HOST', ''),
            'PORT': os.getenv('DB_PORT', ''),
        }
    }
    # Engine-specific tweaks
    if 'mysql' in engine:
        DATABASES['default'].setdefault('OPTIONS', {})['charset'] = 'utf8mb4'
        if not DATABASES['default']['PORT']:
            DATABASES['default']['PORT'] = '3306'
    elif 'postgresql' in engine:
        if not DATABASES['default']['PORT']:
            DATABASES['default']['PORT'] = '5432'
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Seoul'
USE_I18N = True
USE_TZ = True

# Celery Settings
CELERY_BROKER_URL = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/0')
CELERY_RESULT_BACKEND = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/0')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'
CELERY_WORKER_HIJACK_ROOT_LOGGER = False
CELERY_BEAT_SCHEDULE = {}

from django.utils.translation import gettext_lazy as _
LANGUAGES = [
    ('en', _('English')),
    ('ko', _('Korean')),
]

LOCALE_PATHS = [
    BASE_DIR / 'locale',
]

STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'filters': {
        'skip_api_collect': {
            '()': 'core_cert.utils.SuppressApiCollectFilter',
        }
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
            'filters': ['skip_api_collect'],
        },
        'celery_console': {
            'level': 'WARNING',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file': {            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs/django.log'),
            'when': 'midnight',
            'interval': 1,
            'backupCount': 14,
            'formatter': 'verbose',
            'encoding': 'utf-8',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'core_cert': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'celery': {
            'handlers': ['celery_console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'celery.beat': {
            'handlers': ['celery_console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'celery.task': {
            'handlers': ['celery_console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Channels configuration
if os.getenv('REDIS_URL'):
    CHANNEL_LAYERS = {
        'default': {
            'BACKEND': 'channels_redis.core.RedisChannelLayer',
            'CONFIG': {
                "hosts": [os.getenv('REDIS_URL')],
                "capacity": 1500,  # 기본값 100에서 1500으로 상향
                "expiry": 10,      # 메시지 유효 시간 10초
            },
        },
    }
else:
    CHANNEL_LAYERS = {
        'default': {
            'BACKEND': 'channels.layers.InMemoryChannelLayer',
        },
    }

# Proxy settings for Nginx Proxy Manager
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# CSRF Trusted Origins
# CSRF_TRUSTED_SUBNETS: 신뢰할 /24 서브넷 프리픽스를 콤마로 구분 (예: "192.168.10,192.168.50")
# CSRF_TRUSTED_PORTS: 위 서브넷에 적용할 포트 목록 (예: "18180,8000")
# 환경변수로 운영 환경의 사설 대역만 주입하세요. 비워두면 localhost만 허용됩니다.
_csrf_subnets = [s.strip() for s in os.getenv('CSRF_TRUSTED_SUBNETS', '').split(',') if s.strip()]
_csrf_ports = [p.strip() for p in os.getenv('CSRF_TRUSTED_PORTS', '18180,8000').split(',') if p.strip()]

CSRF_TRUSTED_ORIGINS = []
for _subnet in _csrf_subnets:
    for _port in _csrf_ports:
        CSRF_TRUSTED_ORIGINS += [f'http://{_subnet}.{i}:{_port}' for i in range(1, 255)]

# Add localhost for safety
for _port in _csrf_ports:
    CSRF_TRUSTED_ORIGINS += [f'http://127.0.0.1:{_port}', f'http://localhost:{_port}']

# 추가로 명시할 신뢰 오리진 (콤마 구분 전체 URL)
CSRF_TRUSTED_ORIGINS += [o.strip() for o in os.getenv('CSRF_TRUSTED_ORIGINS_EXTRA', '').split(',') if o.strip()]

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = 'login'

# Email Settings (SMTP) - 발송을 위해 실제 계정 정보를 입력하세요.
EMAIL_BACKEND = 'core_cert.email_backend.CustomEmailBackend'
EMAIL_HOST = os.getenv('EMAIL_HOST')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True') == 'True'
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL')

# Session & CSRF cookie names — prevent conflict with other apps on the same host
SESSION_COOKIE_NAME = 'Agncert_sessionid'
CSRF_COOKIE_NAME = 'Agncert_csrftoken'

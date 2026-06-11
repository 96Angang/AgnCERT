# AgnCERT

[English](README.md) | 한국어

AgnCERT는 TLS 인증서를 발급, 갱신, 배포하는 웹 기반 인증서 관리 시스템입니다. `acme.sh`와 DNS-01 검증을 사용하며, 관리 대상 Linux/Windows 서버에 SSH로 인증서를 배포할 수 있습니다.

## 주요 기능

- `acme.sh`를 통한 Let's Encrypt 인증서 발급 및 갱신
- acme-dns 방식 포함 DNS-01 자동화 지원
- 자동 발급 인증서와 수동 업로드 인증서 관리
- Linux 및 Windows/IIS 서버로 인증서 파일 배포
- fullchain, key, cert, chain, root CA, PFX 파일 매핑 설정
- 배포 후 reload 명령 실행 또는 컨테이너 재시작
- 웹 UI에서 배포 로그와 인증서 상태 확인
- 발급, 갱신, 배포, SSH 설정 과정의 WebSocket 실시간 출력
- 한국어/영어 UI 번역

## 기술 스택

- Django 6, Django Channels, Daphne
- MariaDB, PyMySQL
- Valkey: Redis 호환 cache/pubsub/Celery broker
- Celery, django-celery-beat
- Paramiko, SCP 기반 SSH 배포
- Bootstrap, HTMX, Vanilla JavaScript
- Docker Compose

## 빠른 시작

```bash
cp data/.env.example data/.env
# data/.env를 열어 DB, 이메일, 관리자 계정 값을 실제 값으로 설정합니다.

docker compose up -d --build
```

기동 후 접속:

- 애플리케이션: `http://<HOST>:18180`
- Django Admin: `http://<HOST>:18180/admin/`

최초 기동 시 `data/.env`의 `DJANGO_SUPERUSER_*` 값으로 관리자 계정이 1회 자동 생성됩니다.

## 설정

런타임 설정은 `data/.env`에서 로드합니다. `data/.env.example`을 복사해서 사용하세요.

| 분류 | 변수 |
| --- | --- |
| Django | `SECRET_KEY`, `DEBUG`, `DJANGO_SUPERUSER_*` |
| 데이터베이스 | `DB_ENGINE`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, `MARIADB_*` |
| Cache/Broker | `REDIS_URL` |
| Email | `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_USE_TLS`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `DEFAULT_FROM_EMAIL` |
| 접근 제어 | `ADMIN_ALLOWED_NETWORKS`, `CSRF_TRUSTED_SUBNETS`, `CSRF_TRUSTED_PORTS`, `CSRF_TRUSTED_ORIGINS_EXTRA` |

`acme.sh` 계정 이메일은 빌드 인자로 지정할 수 있습니다.

```bash
docker compose build --build-arg ACME_EMAIL=admin@example.com
```

## 프로젝트 구조

```text
AgnCERT/
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
├── data/
│   ├── config/          # Django 설정, ASGI/WSGI, Celery
│   ├── core_cert/       # 인증서, 서버, 배포, 설정 앱
│   ├── templates/       # 공통 템플릿
│   ├── static/          # 정적 파일 소스
│   └── locale/          # i18n 번역 파일
└── make_deploy.sh
```

## 보안 주의

다음 런타임 비밀값과 생성 파일은 커밋하지 마세요.

- `data/.env`
- `data/.secret_key`
- `data/.ssh/`
- `data/acme.sh/`
- `mariadb_data/`
- `valkey_data/`
- `backup/`
- `logs/`

운영 환경에서는 관리자/DB 비밀번호를 강하게 설정하고, SMTP 인증 정보는 환경변수로 관리하며, `DEBUG=False`로 실행하세요.

## 라이선스

이 프로젝트는 MIT License로 배포됩니다. 자세한 내용은 [LICENSE](LICENSE)를 참고하세요.

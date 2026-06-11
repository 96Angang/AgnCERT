# AgnCERT - Claude 세션 컨텍스트

> ⚠️ **작업 범위 (필독)**
> 이 저장소는 `/opt/project/AgnCERT`, `/opt/project/AgnMonitor` 폴더 안에서만 작업한다.
> **운영 원본인 `/opt/AgnCERT`, `/opt/AgnMonitor`(구 `/opt/tgrCERT`, `/opt/tgrMonitor`)는 절대 건드리지 않는다.**
> 문서·코드 내 `/opt/AgnCERT` 등의 절대 경로는 운영 배포 위치를 가리키는 표기일 뿐이며, 실제 편집은 항상 `/opt/project/...` 하위에서만 수행한다.
>
> **명명 규칙:** 이 프로젝트는 닉네임 "앙갱(Agn)" 기준으로, 구 `tgrCERT`→`AgnCERT`, `tgrMonitor`→`AgnMonitor`로 명명한다.
> 컨테이너명(`*_AgnCert`)·쿠키명(`Agncert_*`)·예외 마커(`# AgnCERT_except=true`) 등 식별자도 동일 규칙을 따른다.
> 단, `/opt/tgrDNS`·`/opt/monitor`(외부 참조 프로젝트)와 `postgresql`처럼 우연히 `tgr`이 포함된 단어는 변경 대상이 아니다.

## 1. 프로젝트 개요

**AgnCERT**는 Let's Encrypt 인증서를 자동 발급(acme.sh + acme-dns)하고, 관리 대상 서버(Linux/Windows)에 SSH를 통해 자동 배포·적용하는 통합 인증서 관리 시스템이다.

- **운영 URL:** `http://<HOST>:18180` (Nginx → Django 18180→80→8000 프록시)
- **Django Admin:** `/admin/` (사설 IP 대역만 접근 허용 — `AdminIPRestrictionMiddleware`)
- **기본 관리자 계정:** `data/.env` 의 `DJANGO_SUPERUSER_*` 환경변수로 지정 (최초 1회 자동 생성)
- **기반 참조 프로젝트:** UI·UX는 `/opt/monitor`, 비즈니스 로직은 `/opt/tgrDNS` 참고

---

## 2. 기술 스택

| 레이어 | 기술 |
|--------|------|
| Backend | Django 6.0.5, Django Channels 4 (ASGI/WebSocket), Daphne 4 |
| DB | MariaDB 11.4 (PyMySQL 드라이버, utf8mb4) |
| Cache/PubSub | Valkey 8.0 (Redis 호환, `redis://valkey:6379/0`) |
| Task Queue | Celery 5.6 + django-celery-beat (DB 스케줄러) |
| 인증서 도구 | acme.sh (컨테이너 내장 `/app/acme.sh/`) |
| SSH 배포 | Paramiko + SCP (RSA 4096 / ED25519) |
| Frontend | Bootstrap 5.3, HTMX, Vanilla JS, WebSocket |
| Container | Docker + docker-compose |
| Reverse Proxy | Nginx (alpine) |

---

## 3. 디렉토리 구조

```
/opt/AgnCERT/
├── Dockerfile                  # python:3.12-slim, acme.sh 내장
├── docker-compose.yml          # cert / nginx / mariadb / valkey 4개 서비스
├── nginx.conf                  # WebSocket 업그레이드 포함 프록시 설정
├── make_deploy.sh              # 배포 tarball 생성 스크립트
├── data/                       # Django 소스 (컨테이너 /app 볼륨 마운트)
│   ├── manage.py
│   ├── entrypoint.sh           # DB 대기→migrate→superuser→Celery→runserver
│   ├── requirements.txt
│   ├── config/                 # Django 프로젝트 설정
│   │   ├── settings.py
│   │   ├── urls.py             # /admin/, /i18n/, / (core_cert)
│   │   ├── celery.py           # Celery 앱 설정
│   │   ├── asgi.py             # Channels 라우팅
│   │   ├── wsgi.py
│   │   └── middleware.py       # AdminIPRestrictionMiddleware
│   ├── core_cert/              # 메인 애플리케이션
│   │   ├── models.py
│   │   ├── views.py            # 일반 뷰 + HTMX 부분 뷰
│   │   ├── views_base.py       # (보조 뷰 모음)
│   │   ├── views_stable.py     # (안정화된 뷰 스냅샷)
│   │   ├── urls.py
│   │   ├── consumers.py        # WebSocket: DeployLog, AcmeAction, SSHSetup
│   │   ├── routing.py          # WebSocket URL 패턴
│   │   ├── tasks.py            # Celery 태스크
│   │   ├── deployer.py         # RemoteDeployer (Paramiko+SCP)
│   │   ├── ssh_manager.py      # SSHManager, 키 관리 유틸
│   │   ├── forms.py
│   │   ├── admin.py
│   │   ├── email_backend.py    # 커스텀 SMTP 백엔드
│   │   ├── context_processors.py  # global_settings, 갱신 남은 시간
│   │   ├── utils.py            # verify_site_certificate, Fernet 암호화
│   │   ├── middleware/
│   │   │   └── login_required.py   # 전역 로그인 강제 미들웨어
│   │   ├── management/commands/
│   │   │   ├── cron_renew.py       # acme.sh --cron 실행 + DB 동기화
│   │   │   ├── deploy_domain.py    # SSH 배포 + 검증 (reloadcmd 트리거)
│   │   │   └── scheduler_loop.py
│   │   └── templates/core_cert/
│   │       ├── base.html (→ /data/templates/base.html)
│   │       ├── dashboard.html
│   │       ├── certificate_list.html
│   │       ├── certificate_form.html
│   │       ├── certificate_action.html  # acme.sh 발급/갱신 WebSocket UI
│   │       ├── server_list.html
│   │       ├── server_form.html
│   │       ├── server_ssh_setup.html
│   │       ├── script_list.html
│   │       ├── script_form.html
│   │       ├── script_detail.html      # 배포 실행 WebSocket UI
│   │       ├── ssh_key_manage.html
│   │       ├── settings.html
│   │       ├── confirm_delete.html
│   │       └── login.html
│   ├── acme.sh/                # acme.sh 런타임 데이터 (entrypoint가 복사)
│   ├── .ssh/                   # SSH 키 쌍 (id_rsa, id_ed25519)
│   ├── locale/                 # i18n 번역 (en, ko)
│   ├── static/                 # 소스 정적 파일
│   ├── staticfiles/            # collectstatic 결과 (Nginx에서 서빙)
│   └── logs/                   # django.log (일별 로테이션, 14일 보관)
├── mariadb_data/               # MariaDB 데이터 영속 볼륨
├── valkey_data/                # Valkey 데이터 영속 볼륨
└── backup/                     # 수동 백업 tarball
```

---

## 4. Docker 서비스 구성

```yaml
cert (django_AgnCert):
  ports: 8000:8000
  volumes: ./data:/app, django_static(공유)
  env: REDIS_URL, DB_ENGINE/NAME/USER/PASSWORD/HOST, C_FORCE_ROOT=true

nginx (nginx_AgnCert):
  ports: 18180:80
  volumes: nginx.conf, django_static(읽기전용)
  WebSocket 업그레이드 헤더 포함 프록시

mariadb (mariadb_AgnCert):  image mariadb:11.4
  env: MARIADB_* / DB_* 값은 data/.env 에서 주입 (저장소에는 .env.example 만 포함)
  volumes: ./mariadb_data:/var/lib/mysql

valkey (valkey_AgnCert):    image valkey/valkey:8.0
  volumes: ./valkey_data:/data
```

---

## 5. 데이터 모델 (core_cert/models.py)

### Certificate
| 필드 | 설명 |
|------|------|
| domain | 도메인 (unique) |
| cert_path | 인증서 파일 디렉토리 경로 |
| serial | 인증서 시리얼 번호 |
| expiry_date | 만료일 (DateTimeField) |
| last_renewed | 마지막 갱신일 (auto_now) |
| status | valid / expired / unknown |
| is_wildcard | 와일드카드 여부 |
| allowed_domains | SANs 목록 (텍스트) |
| is_acme | acme.sh 관리 여부 |
| ca_server | letsencrypt / zerossl / letsencrypt_test |
| dns_provider | dns_cf, dns_acmedns 등 |

`renewal_date` 프로퍼티: `expiry_date - RENEWAL_DAYS_BEFORE(GlobalSetting)`

`get_source_file(file_type)`: 실제 파일시스템에서 key/cert/fullchain/pfx 파일명을 탐색

### TargetServer
서버 IP, SSH 포트/사용자, OS 타입(linux/windows), 웹서버 타입(nginx/apache/none),
경로 타입(default/custom), SSL 설정 파일 경로, SSH 연결 상태(pending/success/failure)

### TargetServerSite
서버별로 발견된 도메인:포트 쌍 (배포 후 SSL 설정 파일 파싱으로 자동 갱신)

### DeployScript
Certificate에 연결된 배포 시나리오 단위. `DeploymentTarget` 복수 포함.

### DeploymentTarget
스크립트 → 대상 서버, 원격 경로, reload 명령, prepare_dir/transfer_files/reload_service 플래그

### FileMapping
DeploymentTarget → 파일 타입(fullchain/key/cert/pfx) + 커스텀 파일명 매핑

### DeploymentLog
배포 결과 (status: running/success/failure/partial_success), `details` JSON에 서버별 로그+검증 결과

### GlobalSetting
key-value 전역 설정 저장소. 주요 키:
- `RENEWAL_DAYS_BEFORE` — acme.sh --cron 갱신 기준일 (기본 30)
- `RENEWAL_TIME` — Celery Beat 갱신 스케줄 시각 (기본 03:00)
- `ACMEDNS_BASE_URL` — acme-dns 서버 주소
- `LAST_CRON_RENEWAL` — 마지막 자동 갱신 체크 일시 (기록용)

---

## 6. URL 구조 (core_cert/urls.py, app_name='core_cert')

```
/                           dashboard
/login/                     로그인
/logout/                    로그아웃
/settings/                  전역 설정 페이지
/settings/save/             설정 저장 POST

/certificates/              인증서 목록
/certificates/add/          인증서 추가
/certificates/<pk>/edit/    인증서 수정
/certificates/<pk>/delete/  인증서 삭제 (물리 파일 삭제 옵션 포함)
/certificates/sync/         acme.sh 폴더 스캔 → DB 동기화
/certificates/cron-renew/   수동 갱신 트리거 (백그라운드 스레드)
/certificates/<pk>/issue/           acme.sh 발급 (WebSocket 전환)
/certificates/<pk>/test-issue/      스테이징 테스트 발급
/certificates/<pk>/renew/           갱신
/certificates/<pk>/setup-hook/      reloadcmd 훅 등록
/certificates/<pk>/cname-info/      acme-dns CNAME 정보 반환

/servers/                   서버 목록
/servers/add/               서버 추가
/servers/<pk>/edit/         서버 수정
/servers/<pk>/delete/       서버 삭제
/servers/<pk>/ssh-setup/    SSH 키 등록 (WebSocket)
/servers/<pk>/test-ssh/     SSH 연결 테스트
/servers/<pk>/test-sites/   사이트 SSL 검증
/servers/test-sites-bulk/   일괄 사이트 검증
/servers/bulk-delete/       서버 일괄 삭제
/servers/ssh-keys/          SSH 키 관리 (재생성/수동 저장)

/scripts/                   배포 스크립트 목록
/scripts/add/               스크립트 추가
/scripts/<pk>/edit/         스크립트 수정
/scripts/<pk>/delete/       스크립트 삭제
/scripts/<pk>/              스크립트 상세 (배포 실행 WebSocket)

/logs/<pk>/resolve/         로그 해결 처리
/logs/<pk>/delete/          로그 삭제
/logs/bulk-action/          로그 일괄 처리

WebSocket:
ws/cert/deploy/<script_id>/         → DeployLogConsumer
ws/cert/ssh_setup/<server_id>/      → SSHSetupConsumer
ws/cert/acme_action/<cert_id>/      → AcmeActionConsumer
```

---

## 7. 핵심 로직 플로우

### 인증서 발급/갱신 (WebSocket)
`AcmeActionConsumer.run_acme_command(action)` (consumers.py)
1. `acme.sh --issue/-d <domain> --dns <provider> --ecc --force` 실행 (shell=True, `yes '' |` pipe로 acme-dns 등록 프롬프트 자동 입력)
2. stdout/stderr 실시간 스트리밍 → 프론트엔드
3. 성공 시: `update_certificate_info()` → `ensure_pfx_exists()` → `cert.save()`
4. `manage.py deploy_domain <domain>` 즉시 실행
5. `acme.sh --install-cert --reloadcmd "python3 /app/manage.py deploy_domain <domain>"` 훅 등록

### 인증서 배포 (`deploy_domain` management command)
1. `DeployScript` 순회, 각 스크립트의 `DeploymentTarget` 순회
2. `RemoteDeployer.connect()` (ED25519 → RSA 순서로 시도)
3. `prepare_dir`: `mkdir -p` (Linux) / PowerShell (Windows)
4. `transfer_files`: `FileMapping` 기준 SCP 전송. Windows는 PFX 우선 처리
5. `reload_service`: reload 명령 실행
6. 배포 후 SSL 설정 파일 파싱 → `TargetServerSite` 자동 갱신
7. `verify_site_certificate()` 로 실제 적용 검증 (openssl s_client)

### 자동 갱신 (Celery Beat)
- 스케줄: `IntervalSchedule(every=1, period=DAYS)`, 태스크: `certificate_cron_renew_task`
- `cron_renew` command: `acme.sh --cron --home /app/acme.sh --days <RENEWAL_DAYS_BEFORE>`
- 갱신된 인증서에 대해 acme.sh가 `reloadcmd`(deploy_domain) 자동 실행
- 전체 Certificate DB 만료일 재동기화
- `LAST_CRON_RENEWAL` GlobalSetting 업데이트

### SSH 키 관리 (ssh_manager.py)
- 키 위치: `/app/.ssh/id_rsa`, `/app/.ssh/id_ed25519`
- `ensure_ssh_keys()`: 없으면 자동 생성
- `setup_ssh_key()`: 비밀번호로 원격 서버 접속 → authorized_keys 등록 (Linux: grep 중복 체크, Windows: PowerShell ACL 처리)

---

## 8. 미들웨어 & 보안

- **AdminIPRestrictionMiddleware** (`config/middleware.py`): `/admin/` 접근을 사설 IP 대역(127/10/172.16/192.168)으로 제한. 추가 허용 대역은 `ADMIN_ALLOWED_NETWORKS` 환경변수로 주입
- **LoginRequiredMiddleware** (`core_cert/middleware/login_required.py`): 전체 URL 로그인 강제 (login/logout/admin/set_language 제외)
- `CSRF_TRUSTED_ORIGINS`: `CSRF_TRUSTED_SUBNETS`/`CSRF_TRUSTED_PORTS` 환경변수로 신뢰 대역·포트 지정
- `SECRET_KEY`: `.secret_key` 파일 기반 자동 생성 (환경변수 우선)

---

## 9. 국제화 (i18n)

- `LANGUAGES`: en(English), ko(Korean)
- `LOCALE_PATHS`: `/app/locale/`
- `LocaleMiddleware` 활성화
- `entrypoint.sh`에서 컨테이너 시작 시 `compilemessages` 자동 실행
- 번역 업데이트 도구: `/opt/AgnCERT/update_translations.py`

---

## 10. 로깅

- 파일: `/app/logs/django.log` (TimedRotatingFileHandler, 자정 로테이션, 14일 보관, UTF-8)
- 콘솔: `INFO` 이상 (단, `/api/collect/` 경로는 `SuppressApiCollectFilter`로 억제)
- `core_cert` 로거: `DEBUG` 레벨 파일 + 콘솔
- Celery 로거: `WARNING` 콘솔 + `INFO` 파일

---

## 11. 개발 컨벤션

- **UI 테마**: `/opt/monitor` 스타일 다크/라이트 테마 유지 (`base.html`)
- **HTMX 우선**: 폼셋 추가/삭제, 부분 업데이트는 HTMX로 페이지 새로고침 최소화
- **멀티 OS 분기**: 배포 로직에서 `TargetServer.os_type`으로 Linux(Shell) vs Windows(PowerShell) 명령 구분
- **보안 로그**: SSH 비밀번호 등 민감 정보는 로그에 절대 출력하지 않음
- **실시간 로그**: 인증서 발급·배포 진행 상황은 WebSocket(`consumers.py`)으로 실시간 전달
- **acme.sh 환경**: `--home /app/acme.sh` 항상 명시. `DEBUG`, `CERT_PATH` 환경변수 충돌 방지를 위해 env에서 제거 후 실행
- **PFX 생성**: Windows 배포 시 자동 PFX 생성 (`ensure_pfx_exists()`), 패스워드 `password`, `-legacy -descert` 플래그 포함
- **와일드카드**: `*.domain.com` 형태. 발급 시 base_domain과 `*.base_domain` 모두 `-d`로 전달

---

## 12. 작업 마무리 절차 (필수)

모든 개발·수정 완료 후 다음 순서로 진행:

```bash
# 1. Git 커밋
git add .
git commit -m "작업 내용 요약"

# 2. 프로젝트 백업
cd data && ./backup.sh && cd ..

# 3. 배포 패키지 생성 (소스 핵심 파일만)
./make_deploy_src.sh
```

`make_deploy_src.sh` 포함 목록: `data/core_cert`, `data/config`, `data/locale`, `data/static`, `data/templates`, `data/entrypoint.sh` (소스 핵심만 압축, `deploy_src_<타임스탬프>.tar.gz` 생성)
- 제외: `__pycache__`, `*.pyc`, `*.pyo`, `data/core_cert/migrations/__pycache__`
- 실행 권한이 없으면 `chmod +x make_deploy_src.sh` 후 실행

> 참고: `make_deploy.sh`는 전체 프로젝트를 묶는 구버전 스크립트로, 현재 배포는 `make_deploy_src.sh`(소스 핵심만)를 사용한다.

---

## 13. 주요 운영 명령

```bash
# 컨테이너 관리
docker compose up -d
docker compose down
docker compose logs -f cert
docker compose restart cert

# Django 관리 (컨테이너 내부)
docker exec django_AgnCert python manage.py migrate
docker exec django_AgnCert python manage.py cron_renew
docker exec django_AgnCert python manage.py deploy_domain <domain>
docker exec django_AgnCert python manage.py compilemessages

# DB 직접 접근 (자격증명은 data/.env 의 DB_USER / DB_PASSWORD / DB_NAME 참조)
docker exec -it mariadb_AgnCert mariadb -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME"

# 로그 확인
tail -f /opt/AgnCERT/data/logs/django.log
```

---

## 14. 현재 구현 상태 (2026-06 기준)

**완료:**
- 인증서 발급·갱신·배포 전체 파이프라인
- WebSocket 실시간 로그 스트리밍 (발급/배포/SSH 설정)
- acme-dns CNAME 정보 자동 추출
- PFX 자동 생성 및 Windows 배포
- SSH 키 자동 생성·등록 (Linux + Windows PowerShell ACL)
- Celery Beat 일일 자동 갱신 스케줄
- 갱신 임박일 설정 (`RENEWAL_DAYS_BEFORE`)
- 배포 후 SSL 검증 (openssl s_client)
- 물리 파일 삭제 옵션 포함 삭제 UI
- 다크/라이트 테마, i18n (한/영)
- 서버 사이트 자동 발견 (SSL 설정 파일 파싱)

**미완료/고도화 필요:**
- 대시보드 만료 임박 인증서 시각화 고도화
- Windows IIS 바인딩 자동화
- 배포 성공/실패 알림 (Email/Slack)
- Let's Encrypt 전체 흐름 End-to-End 검증

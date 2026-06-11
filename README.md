# AgnCERT

English | [Korean](README.ko.md)

AgnCERT is a web-based certificate management system that issues, renews, and deploys TLS certificates. It uses `acme.sh` with DNS-01 validation and can deploy certificates to managed Linux or Windows servers over SSH.

## Features

- Issue and renew Let's Encrypt certificates through `acme.sh`
- DNS-01 automation support, including acme-dns style workflows
- Manage automatic and manually uploaded certificates
- Deploy certificate files to remote Linux and Windows/IIS servers
- Configure file mappings for fullchain, key, cert, chain, root CA, and PFX files
- Run reload commands or restart containers after deployment
- Track deployment logs and certificate status from the web UI
- WebSocket-powered live output for issuance, renewal, deployment, and SSH setup
- Korean and English UI translations

## Tech Stack

- Django 6, Django Channels, Daphne
- MariaDB with PyMySQL
- Valkey as Redis-compatible cache, pub/sub, and Celery broker
- Celery and django-celery-beat
- Paramiko and SCP for SSH deployment
- Bootstrap, HTMX, and vanilla JavaScript
- Docker Compose

## Quick Start

```bash
cp data/.env.example data/.env
# Edit data/.env and set real database, email, and admin credentials.

docker compose up -d --build
```

After startup:

- Application: `http://<HOST>:18180`
- Django Admin: `http://<HOST>:18180/admin/`

The first superuser is created once from the `DJANGO_SUPERUSER_*` values in `data/.env`.

## Configuration

All runtime configuration is loaded from `data/.env`. Start from `data/.env.example`.

Important groups:

| Area | Variables |
| --- | --- |
| Django | `SECRET_KEY`, `DEBUG`, `DJANGO_SUPERUSER_*` |
| Database | `DB_ENGINE`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, `MARIADB_*` |
| Cache/Broker | `REDIS_URL` |
| Email | `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_USE_TLS`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `DEFAULT_FROM_EMAIL` |
| Access Control | `ADMIN_ALLOWED_NETWORKS`, `CSRF_TRUSTED_SUBNETS`, `CSRF_TRUSTED_PORTS`, `CSRF_TRUSTED_ORIGINS_EXTRA` |

The `acme.sh` account email can be provided at build time:

```bash
docker compose build --build-arg ACME_EMAIL=admin@example.com
```

## Project Layout

```text
AgnCERT/
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
├── data/
│   ├── config/          # Django project settings, ASGI/WSGI, Celery
│   ├── core_cert/       # Certificate, server, deployment, and settings app
│   ├── templates/       # Shared templates
│   ├── static/          # Static source files
│   └── locale/          # i18n catalogs
└── make_deploy.sh
```

## Security Notes

Do not commit runtime secrets or generated certificate material:

- `data/.env`
- `data/.secret_key`
- `data/.ssh/`
- `data/acme.sh/`
- `mariadb_data/`
- `valkey_data/`
- `backup/`
- `logs/`

For production deployments, set strong admin and database passwords, configure SMTP credentials through environment variables, and run with `DEBUG=False`.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

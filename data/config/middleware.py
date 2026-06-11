from django.http import HttpResponseForbidden
import ipaddress
import os


class AdminIPRestrictionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # 기본 허용 대역 (사설 IP 대역)
        default_networks = [
            '127.0.0.0/8',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
        ]
        # 운영 환경에서 허용할 추가 대역은 ADMIN_ALLOWED_NETWORKS 환경변수로 주입
        # (콤마 구분, 예: "203.0.113.0/24,198.51.100.10/32")
        extra = [n.strip() for n in os.getenv('ADMIN_ALLOWED_NETWORKS', '').split(',') if n.strip()]

        self.allowed_networks = []
        for net in default_networks + extra:
            try:
                self.allowed_networks.append(ipaddress.ip_network(net, strict=False))
            except ValueError:
                continue

    def __call__(self, request):
        if request.path.startswith('/admin/'):
            ip = self.get_client_ip(request)
            if not self.is_ip_allowed(ip):
                return HttpResponseForbidden("Access Denied: Your IP is not authorized.")

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def is_ip_allowed(self, ip):
        # 로컬 호스트 접근은 기본 허용 (개발 편의성)
        if ip in ['127.0.0.1', '::1']:
            return True

        try:
            client_ip = ipaddress.ip_address(ip)
            for network in self.allowed_networks:
                if client_ip in network:
                    return True
        except ValueError:
            return False
        return False

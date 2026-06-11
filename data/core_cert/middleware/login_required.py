from django.shortcuts import redirect
from django.urls import reverse, resolve, Resolver404
from django.conf import settings

class LoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path_info
        
        # 1. 이미 인증된 사용자는 통과
        if request.user.is_authenticated:
            return self.get_response(request)

        # 2. 정적 파일 및 미디어 파일 경로는 인증 제외 (단, 빈 문자열이나 '/'인 경우는 제외)
        if settings.STATIC_URL and settings.STATIC_URL != '/' and path.startswith(settings.STATIC_URL):
            return self.get_response(request)
        
        if hasattr(settings, 'MEDIA_URL') and settings.MEDIA_URL and settings.MEDIA_URL != '/' and path.startswith(settings.MEDIA_URL):
            return self.get_response(request)

        # 3. 예외 URL 리스트 (URL name으로 체크)
        exempt_view_names = [
            'core_cert:login',
            'core_cert:logout',
            'login',
            'logout',
            'admin:login',
            'admin:logout',
            'admin:index',
            'set_language',
        ]

        try:
            resolved = resolve(path)
            # view_name이나 namespace로 체크하여 예외 허용
            if resolved.view_name in exempt_view_names or resolved.namespace == 'admin':
                return self.get_response(request)
        except Resolver404:
            # 매칭되는 URL이 없는 경우 (404)는 그대로 진행하여 404 페이지가 뜨게 함
            return self.get_response(request)

        # 4. 로그인 페이지로 리다이렉트 (next 파라미터 포함)
        login_url = reverse('core_cert:login')
        return redirect(f"{login_url}?next={path}")

from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/cert/deploy/(?P<script_id>\d+)/$', consumers.DeployLogConsumer.as_asgi()),
    re_path(r'ws/cert/ssh_setup/(?P<server_id>\d+)/$', consumers.SSHSetupConsumer.as_asgi()),
    re_path(r'ws/cert/acme_action/(?P<cert_id>\d+)/$', consumers.AcmeActionConsumer.as_asgi()),
]

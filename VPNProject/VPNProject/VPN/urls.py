from django.urls import path
from .views import login_page, login, register, forget_password, send_reset_link, reset_password,ping_host,vpn_connection_success

urlpatterns = [
    path('', login_page, name='login_page'),
    path('login/', login, name='login'),
    path('register/', register, name='register'),
    path('forget-password/', forget_password, name='forget_password'),
    path('send-reset-link/', send_reset_link, name='send_reset_link'),
    path('vpn-success/',vpn_connection_success, name='vpn_connection_success'),
    path('reset-password/<str:token>/', reset_password, name='reset_password'),
    path('ping_host/', ping_host, name='ping_host'),
]

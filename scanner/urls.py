from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('scan/', views.scan, name='scan'),
    path('report/<int:scan_id>/', views.download_report, name='report'),
    path('api/history/', views.history_api, name='history_api'),
    path('owasp/', views.owasp_info, name='owasp_info'),
]
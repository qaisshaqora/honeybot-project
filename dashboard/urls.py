from django.urls import path
from . import views

urlpatterns = [
    # المسارات الأساسية للنظام والداشبورد
    path('', views.home, name='home'),
    path('logs/', views.logs, name='logs'),
    path('alerts/', views.alerts, name='alerts'),
    path('reports/', views.reports, name='reports'),
    path('users/', views.users, name='users'),
    path('settings/', views.settings, name='settings'),
    path('login-attempts/', views.login_attempts, name='login_attempts'),
    path('fake-dashboard/', views.fake_dashboard, name='fake_dashboard'),
    
    # مسارات نظام الدخول والتسجيل والتفعيل
    path('login/', views.login_page, name='login'),
    path('signup/', views.signup_page, name='signup'),
    path('verify-code/', views.verify_code_page, name='verify_code'),
    path('logout/', views.logout_page, name='logout'),
    
    # مختبر الهجمات التجريبية والـ تريغرز القديمة
    path('flood-lab/', views.flood_lab, name='flood_lab'),
    path('api/demo-trigger/', views.demo_command_trigger, name='demo_trigger'),
    
    # -------------------------------------------------------------
    # السطر الجديد المضاف لاستقبال هجوم الـ SQL Injection الحقيقي (كود الدكتور)
    path('api/orders/', views.orders_search_honeypot, name='orders_honeypot'),
]
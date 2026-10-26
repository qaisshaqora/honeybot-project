from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db.models import Count
from django.core.mail import send_mail
from django.conf import settings as django_settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import AttackEvent, SystemSetting, AccessRecord, EmailVerification
import random
import time

# === مخزن عام لحفظ توقيت طلبات كل IP في الذاكرة الحية لمنع مشاكل الـ Cookies مع أداة ab ===
GLOBAL_DOS_CACHE = {}


def generate_verification_code():
    return str(random.randint(100000, 999999))


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '127.0.0.1')


def classify_message_payload(message_text):
    payload_lower = (message_text or '').lower()

    sql_patterns = [
        "' or 1=1",
        '" or 1=1',
        "union select",
        "drop table",
        "select * from",
        "insert into",
        "delete from",
        "--",
    ]

    xss_patterns = [
        "<script>",
        "</script>",
        "onerror=",
        "onload=",
        "javascript:",
        "<img",
        "<svg",
    ]

    traversal_patterns = [
        "../../../",
        "..\\..\\",
        "%00",
        "/etc/passwd",
        "c:\\windows",
        "{{",
        "}}",
        "${",
    ]

    if any(pattern in payload_lower for pattern in sql_patterns):
        return {
            'detected': True,
            'attack_type': 'SQL Injection',
            'severity': 'High',
        }

    if any(pattern in payload_lower for pattern in xss_patterns):
        return {
            'detected': True,
            'attack_type': 'XSS Attempt',
            'severity': 'High',
        }

    if any(pattern in payload_lower for pattern in traversal_patterns):
        return {
            'detected': True,
            'attack_type': 'Unauthorized Access Attempt',
            'severity': 'Medium',
        }

    return {
        'detected': False,
        'attack_type': '',
        'severity': '',
    }


def classify_signup_input(username, email):
    combined_text = f"{username} {email}"
    return classify_message_payload(combined_text)


@login_required(login_url='/login/')
def home(request):
    if not request.user.is_superuser:
        return redirect('/fake-dashboard/')

    attacks = AttackEvent.objects.all().order_by('-event_time')
    recent_attacks = attacks[:5]
    recent_login_attempts = AccessRecord.objects.all().order_by('-login_time')[:8]

    total_attacks = attacks.count()
    ssh_count = AttackEvent.objects.filter(attack_type__icontains='SSH').count()
    sql_count = AttackEvent.objects.filter(attack_type__icontains='SQL').count()
    alerts_count = AttackEvent.objects.filter(severity__in=['High', 'Critical']).count()

    successful_logins = AccessRecord.objects.filter(access_type='Authorized Login').count()
    failed_logins = AccessRecord.objects.filter(access_type='Failed Login').count()

    attack_type_data = (
        AttackEvent.objects.values('attack_type')
        .annotate(total=Count('id'))
        .order_by('-total')
    )

    severity_data = (
        AttackEvent.objects.values('severity')
        .annotate(total=Count('id'))
        .order_by('severity')
    )

    attack_type_labels = [item['attack_type'] for item in attack_type_data]
    attack_type_counts = [item['total'] for item in attack_type_data]

    severity_labels = [item['severity'] for item in severity_data]
    severity_counts = [item['total'] for item in severity_data]

    return render(request, 'home.html', {
        'recent_attacks': recent_attacks,
        'recent_login_attempts': recent_login_attempts,
        'total_attacks': total_attacks,
        'ssh_count': ssh_count,
        'sql_count': sql_count,
        'alerts_count': alerts_count,
        'successful_logins': successful_logins,
        'failed_logins': failed_logins,
        'attack_type_labels': attack_type_labels,
        'attack_type_counts': attack_type_counts,
        'severity_labels': severity_labels,
        'severity_counts': severity_counts,
    })


@login_required(login_url='/login/')
def logs(request):
    if not request.user.is_superuser:
        return redirect('/fake-dashboard/')
    attacks = AttackEvent.objects.all().order_by('-event_time')
    return render(request, 'logs.html', {'attacks': attacks})


@login_required(login_url='/login/')
def alerts(request):
    if not request.user.is_superuser:
        return redirect('/fake-dashboard/')
    attacks = AttackEvent.objects.filter(
        severity__in=['High', 'Critical', 'Medium']
    ).order_by('-event_time')
    return render(request, 'alerts.html', {'attacks': attacks})


@login_required(login_url='/login/')
def reports(request):
    if not request.user.is_superuser:
        return redirect('/fake-dashboard/')
    attacks = AttackEvent.objects.all().order_by('-event_time')
    total_attacks = attacks.count()
    critical_count = AttackEvent.objects.filter(severity='Critical').count()
    high_count = AttackEvent.objects.filter(severity='High').count()
    medium_count = AttackEvent.objects.filter(severity='Medium').count()

    return render(request, 'reports.html', {
        'attacks': attacks,
        'total_attacks': total_attacks,
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
    })


@login_required(login_url='/login/')
def users(request):
    if not request.user.is_superuser:
        return redirect('/fake-dashboard/')
    users_list = User.objects.all().order_by('id')
    return render(request, 'users.html', {'users_list': users_list})


@login_required(login_url='/login/')
def settings(request):
    if not request.user.is_superuser:
        return redirect('/fake-dashboard/')

    setting = SystemSetting.objects.first()

    if not setting:
        setting = SystemSetting.objects.create(
            system_name='Honeypot System',
            alert_level='High',
            email_notifications='Enabled',
            system_mode='Monitoring'
        )

    success_message = ''

    if request.method == 'POST':
        system_name = (request.POST.get('system_name') or setting.system_name or 'Honeypot System').strip()
        alert_level = (request.POST.get('alert_level') or setting.alert_level or 'High').strip()
        email_notifications = (request.POST.get('email_notifications') or setting.email_notifications or 'Enabled').strip()
        system_mode = (request.POST.get('system_mode') or setting.system_mode or 'Monitoring').strip()

        setting.system_name = system_name
        setting.alert_level = alert_level
        setting.email_notifications = email_notifications
        setting.system_mode = system_mode
        setting.save()

        success_message = 'Settings saved successfully.'

    return render(request, 'settings.html', {
        'setting': setting,
        'success_message': success_message,
    })


@login_required(login_url='/login/')
def login_attempts(request):
    if not request.user.is_superuser:
        return redirect('/fake-dashboard/')
    attempts = AccessRecord.objects.all().order_by('-login_time')
    return render(request, 'login_attempts.html', {'attempts': attempts})


@login_required(login_url='/login/')
def fake_dashboard(request):
    if request.user.is_superuser:
        return redirect('/')
    return render(request, 'fake_dashboard.html')


def signup_page(request):
    error_message = ''
    success_message = ''
    client_ip = get_client_ip(request)

    if request.method == 'POST':
        username = (request.POST.get('username') or '').strip()
        email = (request.POST.get('email') or '').strip()
        password = request.POST.get('password') or ''
        confirm_password = request.POST.get('confirm_password') or ''

        detection_result = classify_signup_input(username, email)
        if detection_result['detected']:
            AttackEvent.objects.create(
                attack_type=detection_result['attack_type'],
                source_ip=client_ip,
                severity=detection_result['severity'],
                status='Detected'
            )
            error_message = f'Suspicious signup input detected and logged as {detection_result["attack_type"]}.'
            return render(request, 'signup.html', {
                'error_message': error_message,
                'success_message': success_message,
            })

        if not username or not email or not password or not confirm_password:
            error_message = 'All fields are required.'
        elif password != confirm_password:
            error_message = 'Passwords do not match.'
        elif User.objects.filter(username=username).exists():
            error_message = 'Username already exists.'
        elif User.objects.filter(email=email).exists():
            error_message = 'Email already exists.'
        else:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                is_active=False
            )

            code = generate_verification_code()

            EmailVerification.objects.update_or_create(
                user=user,
                defaults={'code': code}
            )

            send_mail(
                subject='Your Verification Code',
                message=f'Your verification code is: {code}',
                from_email=django_settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )

            request.session['pending_verification_user_id'] = user.id
            return redirect('/verify-code/')

    return render(request, 'signup.html', {
        'error_message': error_message,
        'success_message': success_message,
    })


def verify_code_page(request):
    error_message = ''

    user_id = request.session.get('pending_verification_user_id')
    if not user_id:
        return redirect('/signup/')

    try:
        user = User.objects.get(id=user_id)
        verification = EmailVerification.objects.get(user=user)
    except (User.DoesNotExist, EmailVerification.DoesNotExist):
        return redirect('/signup/')

    if request.method == 'POST':
        entered_code = (request.POST.get('code') or '').strip()

        if entered_code == verification.code:
            user.is_active = True
            user.save()
            verification.delete()
            del request.session['pending_verification_user_id']
            return redirect('/login/')
        else:
            error_message = 'Invalid verification code.'

    return render(request, 'verify_code.html', {
        'error_message': error_message,
        'email': user.email,
    })


def login_page(request):
    if request.user.is_authenticated:
        if request.user.is_superuser:
            return redirect('/')
        return redirect('/fake-dashboard/')

    error_message = ''
    next_url = request.GET.get('next') or request.POST.get('next') or '/'
    failed_attempts = request.session.get('failed_login_attempts', 0)
    client_ip = get_client_ip(request)

    # === [تعديل نهائي] تتبع الـ DoS عبر كاش النظام المباشر لضمان التقاط هجوم أداة ab ===
    current_time = time.time()
    if client_ip not in GLOBAL_DOS_CACHE:
        GLOBAL_DOS_CACHE[client_ip] = []
        
    GLOBAL_DOS_CACHE[client_ip] = [t for t in GLOBAL_DOS_CACHE[client_ip] if current_time - t < 5]
    GLOBAL_DOS_CACHE[client_ip].append(current_time)
    
    if len(GLOBAL_DOS_CACHE[client_ip]) > 15:
        last_logged_key = f"last_log_{client_ip}"
        if current_time - GLOBAL_DOS_CACHE.get(last_logged_key, 0) > 5:
            AttackEvent.objects.create(
                attack_type='High Request Rate (DoS)',
                source_ip=client_ip,
                severity='High',
                status='Detected'
            )
            GLOBAL_DOS_CACHE[last_logged_key] = current_time
    # ===================================================================================

    if request.method == 'POST':
        username = (request.POST.get('username') or '').strip()
        password = request.POST.get('password') or ''

        matched_user = User.objects.filter(username=username).first()

        if matched_user and not matched_user.is_active:
            error_message = 'Your account is not verified yet. Please verify your email first.'
            return render(request, 'login.html', {
                'error_message': error_message,
                'next_url': next_url,
            })

        user = authenticate(request, username=username, password=password)

        if user is not None:
            request.session['failed_login_attempts'] = 0

            AccessRecord.objects.create(
                username=user.username,
                email=user.email,
                source_ip=client_ip,
                access_type='Authorized Login'
            )

            login(request, user)

            if user.is_superuser:
                return redirect(next_url)

            return redirect('/fake-dashboard/')

        failed_attempts += 1
        request.session['failed_login_attempts'] = failed_attempts

        AccessRecord.objects.create(
            username=username if username else 'unknown',
            email=matched_user.email if matched_user else None,
            source_ip=client_ip,
            access_type='Failed Login'
        )

        if failed_attempts >= 3:
            AttackEvent.objects.create(
                attack_type='Brute Force Login Attempt',
                source_ip=client_ip,
                severity='High',
                status='Detected'
            )
            request.session['failed_login_attempts'] = 0
            error_message = 'Brute-force login activity detected. Access blocked.'
        else:
            error_message = 'Invalid username or password'

    return render(request, 'login.html', {
        'error_message': error_message,
        'next_url': next_url,
    })


@login_required(login_url='/login/')
def flood_lab(request):
    if not request.user.is_superuser:
        return redirect('/fake-dashboard/')

    success_message = ''
    simulated_requests = 0
    threshold = 20
    client_ip = get_client_ip(request)

    if request.method == 'POST':
        try:
            simulated_requests = int(request.POST.get('request_count', 0))
        except ValueError:
            simulated_requests = 0

        time.sleep(0.3)

        if simulated_requests >= threshold:
            AttackEvent.objects.create(
                attack_type='DDoS Simulation',
                source_ip=client_ip,
                severity='High',
                status='Detected'
            )
            success_message = f'Request flood detected. {simulated_requests} simulated requests triggered a DDoS Simulation event.'
        else:
            success_message = f'{simulated_requests} simulated requests were submitted. Threshold not exceeded.'

    return render(request, 'flood_lab.html', {
        'success_message': success_message,
        'threshold': threshold,
    })


@csrf_exempt
def demo_command_trigger(request):
    if request.method != 'POST':
        return JsonResponse({
            'ok': False,
            'message': 'POST required'
        }, status=405)

    demo_key = (request.POST.get('demo_key') or '').strip()
    scenario = (request.POST.get('scenario') or '').strip().lower()

    if demo_key != 'KALI_DEMO_2026':
        return JsonResponse({
            'ok': False,
            'message': 'Invalid demo key'
        }, status=403)

    client_ip = get_client_ip(request)

    if scenario == 'rate':
        AttackEvent.objects.create(
            attack_type='High Request Rate',
            source_ip=client_ip,
            severity='High',
            status='Detected'
        )
        return JsonResponse({
            'ok': True,
            'message': 'High Request Rate event logged successfully.',
            'source_ip': client_ip
        })

    if scenario == 'auth-flood':
        AttackEvent.objects.create(
            attack_type='Authentication Flood',
            source_ip=client_ip,
            severity='High',
            status='Detected'
        )
        return JsonResponse({
            'ok': True,
            'message': 'Authentication Flood event logged successfully.',
            'source_ip': client_ip
        })

    return JsonResponse({
        'ok': False,
        'message': 'Unknown scenario'
    }, status=400)


def logout_page(request):
    logout(request)
    return redirect('/login/')


@csrf_exempt
def orders_search_honeypot(request):
    client_ip = get_client_ip(request)
    ship_city = request.GET.get('ShipCity', '') or request.POST.get('ShipCity', '')
    
    if ship_city:
        classification = classify_message_payload(ship_city)
        
        if classification['detected'] and classification['attack_type'] == 'SQL Injection':
            AttackEvent.objects.create(
                attack_type='SQL Injection',
                source_ip=client_ip,
                severity=classification['severity'],
                status='Detected'
            )
            return JsonResponse({
                "error": "Internal Server Error",
                "exception": "Syntax error in SQL statement near 'OrdersTable'"
            }, status=500)

    return JsonResponse({
        "status": "Success",
        "message": f"Results for city: {ship_city if ship_city else 'None'}"
    })
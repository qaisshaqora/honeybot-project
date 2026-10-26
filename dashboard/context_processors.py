from .models import SystemSetting

def system_settings(request):
    setting = SystemSetting.objects.first()

    if setting:
        return {
            'system_name': setting.system_name
        }

    return {
        'system_name': 'Honeypot System'
    }
from django.contrib import admin
from .models import AttackEvent, SystemSetting, AccessRecord


@admin.register(AttackEvent)
class AttackEventAdmin(admin.ModelAdmin):
    list_display = ('id', 'attack_type', 'source_ip', 'severity', 'status', 'event_time')
    search_fields = ('attack_type', 'source_ip', 'severity', 'status')
    list_filter = ('severity', 'status', 'attack_type')
    readonly_fields = ('source_ip', 'event_time', 'mitigation_steps')

    fieldsets = (
        ('Attack Information', {
            'fields': ('attack_type', 'severity', 'status')
        }),
        ('Generated Automatically', {
            'fields': ('source_ip', 'event_time', 'mitigation_steps')
        }),
    )


@admin.register(AccessRecord)
class AccessRecordAdmin(admin.ModelAdmin):
    list_display = ('id', 'username', 'email', 'source_ip', 'access_type', 'login_time')
    search_fields = ('username', 'email', 'source_ip', 'access_type')
    readonly_fields = ('source_ip', 'login_time')


@admin.register(SystemSetting)
class SystemSettingAdmin(admin.ModelAdmin):
    list_display = ('system_name', 'alert_level', 'email_notifications', 'system_mode')
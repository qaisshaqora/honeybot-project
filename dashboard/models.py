from django.db import models
from django.contrib.auth.models import User
import random


def generate_random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def get_mitigation_steps(attack_type):
    mitigations = {
        'SSH Brute Force': 'Enable rate limiting, use strong passwords, disable root login, and enable MFA.',
        'SQL Injection': 'Use parameterized queries, validate inputs, sanitize user data, and deploy a WAF.',
        'XSS Attempt': 'Escape output, sanitize user input, and enforce Content Security Policy (CSP).',
        'Admin Panel Probe': 'Restrict admin access by IP, use strong authentication, and monitor suspicious requests.',
        'Brute Force Login': 'Enable account lockout, add CAPTCHA, and enforce MFA.',
        'Brute Force Login Attempt': 'Lock the source after repeated failures, apply rate limiting, enable MFA, and review login activity.',
        'Malicious XSS Payload': 'Sanitize payloads, validate input, and deploy CSP protection.',
        'Recon Scan': 'Monitor abnormal scanning behavior, block suspicious IPs, and enable IDS/IPS.',
        'Suspicious Login Attempt': 'Enable MFA, log failed attempts, alert the administrator, and block repeated attempts.',
        'Credential Stuffing': 'Enable bot protection, MFA, and lock repeated failed attempts.',
        'DDoS Simulation': 'Activate rate limiting, enable protection mode, use CDN/WAF, and temporarily reduce exposed services.',
        'Unauthorized Access Attempt': 'Restrict access to admins only, log unauthorized attempts, and alert the administrator.',
    }
    return mitigations.get(attack_type, 'Investigate the event, monitor the source IP, and apply standard security controls.')


class AttackEvent(models.Model):
    ATTACK_TYPES = [
        ('SSH Brute Force', 'SSH Brute Force'),
        ('SQL Injection', 'SQL Injection'),
        ('XSS Attempt', 'XSS Attempt'),
        ('Admin Panel Probe', 'Admin Panel Probe'),
        ('Brute Force Login', 'Brute Force Login'),
        ('Brute Force Login Attempt', 'Brute Force Login Attempt'),
        ('Malicious XSS Payload', 'Malicious XSS Payload'),
        ('Recon Scan', 'Recon Scan'),
        ('Suspicious Login Attempt', 'Suspicious Login Attempt'),
        ('Credential Stuffing', 'Credential Stuffing'),
        ('DDoS Simulation', 'DDoS Simulation'),
        ('Unauthorized Access Attempt', 'Unauthorized Access Attempt'),
    ]

    SEVERITY_LEVELS = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]

    STATUS_CHOICES = [
        ('Detected', 'Detected'),
        ('Investigating', 'Investigating'),
        ('Blocked', 'Blocked'),
        ('Mitigated', 'Mitigated'),
    ]

    attack_type = models.CharField(max_length=100, choices=ATTACK_TYPES)
    source_ip = models.CharField(max_length=50, blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS)
    event_time = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='Detected')
    mitigation_steps = models.TextField(blank=True)

    def save(self, *args, **kwargs):
        if not self.source_ip:
            self.source_ip = generate_random_ip()

        if not self.mitigation_steps:
            self.mitigation_steps = get_mitigation_steps(self.attack_type)

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.attack_type} - {self.source_ip}"


class AccessRecord(models.Model):
    username = models.CharField(max_length=150)
    email = models.EmailField(blank=True, null=True)
    source_ip = models.CharField(max_length=50, blank=True)
    login_time = models.DateTimeField(auto_now_add=True)
    access_type = models.CharField(max_length=50, default='Authorized Login')

    def save(self, *args, **kwargs):
        if not self.source_ip:
            self.source_ip = generate_random_ip()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.username} - {self.access_type}"


class EmailVerification(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.code}"


class SystemSetting(models.Model):
    system_name = models.CharField(max_length=200, default='Honeypot System')
    alert_level = models.CharField(max_length=20, default='High')
    email_notifications = models.CharField(max_length=20, default='Enabled')
    system_mode = models.CharField(max_length=20, default='Monitoring')

    def __str__(self):
        return self.system_name
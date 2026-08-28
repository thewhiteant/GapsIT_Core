from django.db import migrations

SEED_TYPES = [
    {
        "code": "account_security",
        "name": "Account & Security",
        "description": "Email verification, password-changed alerts. Cannot be turned off.",
        "category": "security",
        "is_mandatory": True,
        "default_enabled": True,
    },
    {
        "code": "account_updates",
        "name": "Account Updates",
        "description": "Welcome email and role/promotion changes on your own account.",
        "category": "account",
        "is_mandatory": False,
        "default_enabled": True,
    },
    {
        "code": "admin_broadcast",
        "name": "Admin Notices",
        "description": "Announcements and updates sent by an admin from the broadcast page.",
        "category": "admin",
        "is_mandatory": False,
        "default_enabled": True,
    },
]


def seed_notification_types(apps, schema_editor):
    NotificationType = apps.get_model("notifications", "NotificationType")
    for data in SEED_TYPES:
        NotificationType.objects.get_or_create(code=data["code"], defaults=data)


def remove_notification_types(apps, schema_editor):
    NotificationType = apps.get_model("notifications", "NotificationType")
    NotificationType.objects.filter(code__in=[d["code"] for d in SEED_TYPES]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("notifications", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_notification_types, remove_notification_types),
    ]

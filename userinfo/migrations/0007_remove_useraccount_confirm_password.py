# Generated by Django 5.2 on 2025-05-10 21:32

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('userinfo', '0006_alter_useraccount_email'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='useraccount',
            name='confirm_password',
        ),
    ]

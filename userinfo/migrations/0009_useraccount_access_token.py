# Generated by Django 5.2 on 2025-05-11 03:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userinfo', '0008_useraccount_confirm_password'),
    ]

    operations = [
        migrations.AddField(
            model_name='useraccount',
            name='access_token',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
    ]

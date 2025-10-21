from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0002_userprofile_cleartext_password'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='cleartext_password',
        ),
    ]

# Generated manually to handle field renaming

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('notifications', '0002_initial'),
    ]

    operations = [
        # Rename Notification model fields
        migrations.RenameField(
            model_name='notification',
            old_name='id',
            new_name='notificationId',
        ),
        migrations.RenameField(
            model_name='notification',
            old_name='user',
            new_name='userId',
        ),
        migrations.RenameField(
            model_name='notification',
            old_name='is_read',
            new_name='isRead',
        ),
        migrations.RenameField(
            model_name='notification',
            old_name='created_at',
            new_name='createdAt',
        ),
    ]
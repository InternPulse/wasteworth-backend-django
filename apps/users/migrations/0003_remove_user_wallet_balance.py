# Generated migration to remove wallet_balance field
# This field was redundant - balance is now fetched from related Wallet model

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_alter_user_address_location'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='wallet_balance',
        ),
    ]

# Generated manually for adding database indexes to WalletTransaction model

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('wallet', '0003_alter_wallettransaction_options_wallet_created_at_and_more'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='wallettransaction',
            index=models.Index(fields=['wallet', '-created_at'], name='wallet_created_idx'),
        ),
        migrations.AddIndex(
            model_name='wallettransaction',
            index=models.Index(fields=['user', '-created_at'], name='user_created_idx'),
        ),
        migrations.AddIndex(
            model_name='wallettransaction',
            index=models.Index(fields=['wallet', 'transaction_type', '-created_at'], name='wallet_type_idx'),
        ),
        migrations.AddIndex(
            model_name='wallettransaction',
            index=models.Index(fields=['user', 'transaction_type'], name='user_type_idx'),
        ),
        migrations.AddIndex(
            model_name='wallettransaction',
            index=models.Index(fields=['status', '-created_at'], name='status_created_idx'),
        ),
    ]

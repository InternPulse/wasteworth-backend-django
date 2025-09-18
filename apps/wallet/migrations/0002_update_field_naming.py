# Generated manually to handle field renaming

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('wallet', '0001_initial'),
    ]

    operations = [
        # Rename Wallet model fields
        migrations.RenameField(
            model_name='wallet',
            old_name='id',
            new_name='walletId',
        ),
        migrations.RenameField(
            model_name='wallet',
            old_name='user',
            new_name='userId',
        ),
        migrations.RenameField(
            model_name='wallet',
            old_name='updated_at',
            new_name='updatedAt',
        ),

        # Rename WalletTransaction model fields
        migrations.RenameField(
            model_name='wallettransaction',
            old_name='id',
            new_name='transactionId',
        ),
        migrations.RenameField(
            model_name='wallettransaction',
            old_name='user',
            new_name='userId',
        ),
        migrations.RenameField(
            model_name='wallettransaction',
            old_name='transaction_type',
            new_name='transactionType',
        ),
        migrations.RenameField(
            model_name='wallettransaction',
            old_name='payment_method',
            new_name='paymentMethod',
        ),
        migrations.RenameField(
            model_name='wallettransaction',
            old_name='created_at',
            new_name='createdAt',
        ),

        # Rename Referral model fields
        migrations.RenameField(
            model_name='referral',
            old_name='id',
            new_name='referralId',
        ),
        migrations.RenameField(
            model_name='referral',
            old_name='referrer',
            new_name='referrerId',
        ),
        migrations.RenameField(
            model_name='referral',
            old_name='referee',
            new_name='refereeId',
        ),
        migrations.RenameField(
            model_name='referral',
            old_name='bonus_amount',
            new_name='bonusAmount',
        ),
        migrations.RenameField(
            model_name='referral',
            old_name='created_at',
            new_name='createdAt',
        ),
    ]
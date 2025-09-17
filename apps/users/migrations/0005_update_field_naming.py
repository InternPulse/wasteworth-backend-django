# Generated manually to handle field renaming

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0004_alter_user_email'),
    ]

    operations = [
        # Rename User model fields
        migrations.RenameField(
            model_name='user',
            old_name='id',
            new_name='userId',
        ),
        migrations.RenameField(
            model_name='user',
            old_name='referral_code',
            new_name='referralCode',
        ),
        migrations.RenameField(
            model_name='user',
            old_name='referred_by',
            new_name='referredBy',
        ),
        migrations.RenameField(
            model_name='user',
            old_name='created_at',
            new_name='createdAt',
        ),
        migrations.RenameField(
            model_name='user',
            old_name='updated_at',
            new_name='updatedAt',
        ),

        # Remove old location fields and add new location field
        migrations.RemoveField(
            model_name='user',
            name='location_lat',
        ),
        migrations.RemoveField(
            model_name='user',
            name='location_lng',
        ),
        migrations.RemoveField(
            model_name='user',
            name='address_location',
        ),
        migrations.AddField(
            model_name='user',
            name='location',
            field=models.JSONField(blank=True, null=True),
        ),

        # Add wallet balance field
        migrations.AddField(
            model_name='user',
            name='walletBalance',
            field=models.DecimalField(decimal_places=2, default=0.0, max_digits=10),
        ),

        # Update role choices
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('user', 'User'), ('collector', 'Collector'), ('admin', 'Admin')], default='user', max_length=20),
        ),

        # Make email optional
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.EmailField(blank=True, null=True, unique=True),
        ),

        # Rename OTP model fields
        migrations.RenameField(
            model_name='otp',
            old_name='id',
            new_name='otpId',
        ),
        migrations.RenameField(
            model_name='otp',
            old_name='user',
            new_name='userId',
        ),
        migrations.RenameField(
            model_name='otp',
            old_name='hashed_otp',
            new_name='hashedOtp',
        ),
        migrations.RenameField(
            model_name='otp',
            old_name='expires_at',
            new_name='expiresAt',
        ),
        migrations.RenameField(
            model_name='otp',
            old_name='created_at',
            new_name='createdAt',
        ),
    ]
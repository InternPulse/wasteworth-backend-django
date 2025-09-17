# Generated manually to handle field renaming

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('listings', '0002_initial'),
    ]

    operations = [
        # Rename Listing model fields
        migrations.RenameField(
            model_name='listing',
            old_name='id',
            new_name='listingId',
        ),
        migrations.RenameField(
            model_name='listing',
            old_name='user',
            new_name='userId',
        ),
        migrations.RenameField(
            model_name='listing',
            old_name='collector',
            new_name='collectorId',
        ),
        migrations.RenameField(
            model_name='listing',
            old_name='waste_type',
            new_name='wasteType',
        ),
        migrations.RenameField(
            model_name='listing',
            old_name='reward_estimate',
            new_name='rewardEstimate',
        ),
        migrations.RenameField(
            model_name='listing',
            old_name='final_reward',
            new_name='finalReward',
        ),
        migrations.RenameField(
            model_name='listing',
            old_name='created_at',
            new_name='createdAt',
        ),
        migrations.RenameField(
            model_name='listing',
            old_name='updated_at',
            new_name='updatedAt',
        ),

        # Remove old location fields and add new location field
        migrations.RemoveField(
            model_name='listing',
            name='pickup_location_lat',
        ),
        migrations.RemoveField(
            model_name='listing',
            name='pickup_location_lng',
        ),
        migrations.AddField(
            model_name='listing',
            name='pickupLocation',
            field=models.JSONField(),
        ),

        # Rename MarketplaceListing model fields
        migrations.RenameField(
            model_name='marketplacelisting',
            old_name='id',
            new_name='marketplaceId',
        ),
        migrations.RenameField(
            model_name='marketplacelisting',
            old_name='pickup_id',
            new_name='pickupId',
        ),
        migrations.RenameField(
            model_name='marketplacelisting',
            old_name='recycler',
            new_name='recyclerId',
        ),
        migrations.RenameField(
            model_name='marketplacelisting',
            old_name='waste_type',
            new_name='wasteType',
        ),
        migrations.RenameField(
            model_name='marketplacelisting',
            old_name='quantity_kg',
            new_name='quantityKg',
        ),
        migrations.RenameField(
            model_name='marketplacelisting',
            old_name='escrow_status',
            new_name='escrowStatus',
        ),
        migrations.RenameField(
            model_name='marketplacelisting',
            old_name='created_at',
            new_name='createdAt',
        ),
    ]
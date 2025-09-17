# Generated manually to revert signup logic changes

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0005_update_field_naming'),
    ]

    operations = [
        # Make name optional (nullable)
        migrations.AlterField(
            model_name='user',
            name='name',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),

        # Make phone optional (nullable)
        migrations.AlterField(
            model_name='user',
            name='phone',
            field=models.CharField(blank=True, max_length=20, null=True, unique=True),
        ),

        # Keep email required (non-nullable) - no change needed since it was already required
        # The model already has email as required, so no migration needed for this field
    ]
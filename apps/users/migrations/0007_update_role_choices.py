# Generated manually to update role choices

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0006_revert_signup_logic'),
    ]

    operations = [
        # Update role choices and default value
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.CharField(
                choices=[('disposer', 'Disposer'), ('recycler', 'Recycler'), ('admin', 'Admin')],
                default='disposer',
                max_length=20
            ),
        ),
    ]
# Generated by Django 5.0.1 on 2024-01-10 07:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ecommerceapp', '0004_alter_userdetails_password'),
    ]

    operations = [
        migrations.AddField(
            model_name='products',
            name='image',
            field=models.ImageField(default=None, upload_to='images/'),
        ),
    ]
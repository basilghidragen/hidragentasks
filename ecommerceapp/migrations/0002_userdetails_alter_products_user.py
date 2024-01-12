# Generated by Django 5.0.1 on 2024-01-10 04:18

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ecommerceapp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50)),
                ('username', models.CharField(max_length=50)),
                ('password', models.CharField(max_length=50)),
                ('token', models.JSONField()),
            ],
        ),
        migrations.AlterField(
            model_name='products',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='ecommerceapp.userdetails'),
        ),
    ]

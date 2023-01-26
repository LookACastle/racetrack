# Generated by Django 3.2.6 on 2021-10-07 16:56

from django.db import migrations, models
import django.db.models.deletion
import lifecycle.django.registry.models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0009_userprofile_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='esc',
            name='jobs',
        ),
        migrations.AddField(
            model_name='deployment',
            name='job_version',
            field=models.CharField(default='0.0.1', max_length=256),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='job',
            name='version',
            field=models.CharField(default='0.0.1', max_length=256),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='job',
            name='name',
            field=models.CharField(max_length=512),
        ),
        migrations.AlterUniqueTogether(
            name='job',
            unique_together={('name', 'version')},
        ),
        migrations.CreateModel(
            name='JobFamily',
            fields=[
                ('id', models.CharField(default=lifecycle.django.registry.models.new_uuid, max_length=36, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=512, unique=True)),
                ('allowed_job_families', models.ManyToManyField(blank=True, to='registry.JobFamily')),
            ],
        ),
        migrations.RemoveField(
            model_name='job',
            name='allowed_jobs',
        ),
        migrations.AddField(
            model_name='esc',
            name='allowed_job_families',
            field=models.ManyToManyField(blank=True, related_name='allowed_escs', to='registry.JobFamily'),
        ),
        migrations.AddField(
            model_name='job',
            name='family',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='registry.jobfamily'),
        ),
    ]

# Generated by Django 3.2.6 on 2021-10-07 16:58

from django.db import migrations, models
import django.db.models.deletion


def initialize_job_families(apps, schema_editor):
    Job = apps.get_model('registry', 'Job')
    JobFamily = apps.get_model('registry', 'JobFamily')

    for job in Job.objects.all():
        job.family = create_job_family_if_not_exist(job.name, JobFamily)
        if not job.version:
            job.version = '0.0.1'
        job.save()


def create_job_family_if_not_exist(job_name: str, JobFamily):
    try:
        return JobFamily.objects.get(name=job_name)
    except JobFamily.DoesNotExist:
        new_model = JobFamily(
            name=job_name,
        )
        new_model.save()
        return new_model


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0010_auto_20211007_1656'),
    ]

    operations = [
        migrations.RunPython(initialize_job_families),
        # disallow null family
        migrations.AlterField(
            model_name='job',
            name='family',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='registry.jobfamily'),
        ),
    ]

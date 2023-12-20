# Generated by Django 4.1.13 on 2023-12-05 11:42

from django.db import migrations
from packageurl import normalize_qualifiers


class Migration(migrations.Migration):

    def copy_qualifiers_temp(apps, schema_editor):
        """
        Bulk update qualifiers_temp from the legacy JSON field
        """
        Package = apps.get_model("vulnerabilities", "Package")
        updatables = []
        for package in Package.objects.all():
            qualifiers_temp = package.qualifiers_temp
            package.qualifiers = qualifiers_temp
            updatables.append(package)
        
        updated = Package.objects.bulk_update(
            objs = updatables,
            fields=["qualifiers",], 
            batch_size=500,
        )
        print(f"Copied {updated} qualifiers_temp to qualifiers")            



    dependencies = [
        ("vulnerabilities", "0048_alter_package_unique_together_and_more"),
    ]

    operations = [
        migrations.RunPython(copy_qualifiers_temp, reverse_code=migrations.RunPython.noop),
    ]

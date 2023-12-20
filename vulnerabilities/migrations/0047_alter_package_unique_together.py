# Generated by Django 4.1.7 on 2023-12-05 13:42

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0046_copy_qualifiers_to_qualifiers_temp"),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name="package",
            unique_together={
                ("type", "namespace", "name", "version", "qualifiers", "subpath", "qualifiers_temp")
            },
        ),
    ]

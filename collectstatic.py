import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")

import django
django.setup()

from django.core.management import call_command

call_command("collectstatic", interactive=False)
print("DONE")
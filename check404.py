import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
import django
django.setup()

from django.test import Client

r = Client(HTTP_HOST="gapsit.bd").get("/core/does-not-exist-xyz/")
print("STATUS:", r.status_code)
print("CONTENT:", r.content[:100])
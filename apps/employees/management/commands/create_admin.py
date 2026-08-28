from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Creates a default superuser if one does not already exist"

    def handle(self, *args, **options):
        User = get_user_model()
        username = "whiteant"
        email = "trafi227@gmail.com"
        password = "whiteant321@"

        if User.objects.filter(username=username).exists():
            self.stdout.write("User already exists")
        else:
            User.objects.create_superuser(username, email, password)
            self.stdout.write("Superuser created successfully")


            # apps/employees/management/commands/
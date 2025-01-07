# from django.contrib.auth.models import User


# def generate_random_password():
#     print("here")
#     print(dir(User.objects))
#     return User.objects.make_random_password()

from django.contrib.auth.models import User
import secrets
import string

def generate_random_password(length=12):
    try:
        # Attempt to use Django's UserManager make_random_password method
        return User.objects.make_random_password(length=length)
    except AttributeError:
        # If it fails, use a manual fallback implementation
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password

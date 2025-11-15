import os

from django.db import models


def upload_path(user, filename):
    extension = os.path.splitext(filename)[1]
    return 'avatar_%s%s' % (user.pk, extension)


class UserProfile(models.Model):
    user = models.OneToOneField('auth.User', on_delete=models.CASCADE)
    avatar = models.ImageField(upload_to=upload_path, blank=True)
    bio = models.TextField(max_length=255, blank=True)

    # NOTE: The cleartext_password field was removed to avoid persisting
    # plaintext secrets. A migration has been added to remove the field
    # from the schema in a controlled manner.

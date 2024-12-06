import re
from django.core.exceptions import ValidationError
from django.conf import settings
from django.core.mail import send_mail


def validate_password(old_password, new_password, confirm_password, user):
    if not user.check_password(old_password):
        raise ValidationError({"old_password": "Old password did not match"})
    if new_password != confirm_password:
            raise ValidationError("Password and confirm password doesn't match")
    if len(new_password) < 8 or not any(char.isupper() for char in new_password) or not re.search(r"[!@#$%^&*(),.?\"{}|<>]", new_password):
        raise ValidationError("""Password must be at least 8 characters long.\nPassword must include at least one uppercase letter.\nPassword must include at least one special character (!@#$%^&*(),.?\"{}|<>).""")


def send_reset_mail(subject, message, user):
    send_mail(
    subject,
    message,
    settings.EMAIL_HOST_USER,
    user,
    fail_silently=False,
)

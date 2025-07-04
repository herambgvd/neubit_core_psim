# Signal handlers for automatic profile creation
from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.users.models import User


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Automatically create user profile when user is created."""
    if created and not instance.is_service_account:
        UserProfile.objects.create(user=instance)
        logger.info(
            "user_profile_created",
            user_id=instance.id,
            username=instance.username
        )


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Save user profile when user is saved."""
    if not instance.is_service_account and hasattr(instance, 'profile'):
        instance.profile.save()

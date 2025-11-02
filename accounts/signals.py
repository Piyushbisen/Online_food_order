from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from .models import User, UserProfile



  
@receiver(post_save, sender=User)
def post_save_create_profile_receiver(sender, instance, created, **kwargs):
    print(created)
    if created:
        UserProfile.objects.create(User=instance)
        print('user profile created ')
    else:
        try:
            profile =UserProfile.objects.get(User=instance)
            profile.save()
        except:
            # create the user profile if not created 
            UserProfile.objects.create(User=instance)
            print('user profile is not exist bu ti created one')
        print('user updated')

@receiver(pre_save, sender=User)
def pre_save_profile_receiver(sender, instance, **kwargs):
    print(instance.username,'this user is being saved')
# post_save.connect(post_save_create_profile_receiver, sender=User)
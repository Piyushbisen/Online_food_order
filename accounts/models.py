from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager


# Create your models here.
class usermanager(BaseUserManager): #baseusermanager is inbuilt class in django which helps to create user and superuser
    def create_user(self, first_name , last_name ,username, email, password=None, **extra_fields):
        if not email:      
            raise ValueError('Email is required')
        
        if not username:
            raise ValueError('Username is required')
        
        user = self.model(
            email = self.normalize_email(email), #it will convert email to lowercase
            username = username,
            first_name = first_name,
            last_name = last_name,
        )
        user.set_password(password) #it will convert password to hash format
        user.save(using=self._db)
        return user
    
    def create_superuser(self, first_name , last_name , username, email, password=None, **extra_fields):
        user = self.create_user(
            email = self.normalize_email(email),
            username = username,
            password = password,
            first_name = first_name,
            last_name = last_name,
        )
        user.is_admin = True
        user.is_active = True
        user.is_staff = True
        user.is_superadmin = True
        user.save(using=self._db)
        return user
    

class User(AbstractBaseUser):
    VENDOR = 1
    CUSTOMER = 2
    ROLE_CHOICE = (
        (VENDOR, 'vendor'),
        (CUSTOMER, 'Customer'),
    )
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    phone_number = models.CharField(max_length=50)
    role = models.PositiveSmallIntegerField(choices=ROLE_CHOICE, blank=True, null=True) #positive small integer field is used to store small positive integers

    # REQUIRED_FIELDS
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now_add=True)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_superadmin = models.BooleanField(default=False)
    

    USERNAME_FIELD = 'email'  #username field is email
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name'] #required fields for creating superuser

    objects = usermanager() #usermanager is the custom manager for user model

    def __str__(self): #string representation of the user
        return self.email
    
    def has_perm(self, perm, obj=None): #to check if user has permission
        return self.is_admin
    
    def has_module_perms(self, app_label): #to check if user has module permissions
        return True 
    

class UserProfile(models.Model):
    User = models.OneToOneField(User, on_delete = models.CASCADE, blank=True, null=True)
    profile_picture = models.ImageField(upload_to='users/profile_picture', blank=True, null=True)
    cover_picture = models.ImageField(upload_to='users/cover_picture', blank=True, null=True)
    address_line_1 = models.CharField(max_length=50, blank=True, null=True)
    address_line_2 = models.CharField(max_length=50, blank=True, null=True)
    country  = models.CharField(max_length=15, blank=True, null=True)
    state = models.CharField(max_length=15, blank=True, null=True)
    city = models.CharField(max_length=15, blank=True, null=True)
    pincode = models.CharField(max_length=6, blank=True, null=True)
    latitude = models.CharField(max_length=20, blank=True, null=True)
    longitude = models.CharField(max_length=20, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.User.email
  
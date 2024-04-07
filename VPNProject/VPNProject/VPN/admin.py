from django.contrib import admin

# Register your models here.
from .models import LoginUser, CustomUser

admin.site.register(LoginUser)
admin.site.register(CustomUser)

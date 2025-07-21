from django.contrib import admin
from .models import DeviceType, Device, DeviceLog, DeviceRequest
from .models import ESPDevice, UserProfile

admin.site.register(DeviceType)
admin.site.register(Device)
admin.site.register(DeviceLog)
admin.site.register(DeviceRequest)
admin.site.register(ESPDevice)
admin.site.register(UserProfile)

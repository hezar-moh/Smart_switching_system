from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone


class DeviceType(models.Model):
    ICON_CHOICES = [
        ('💡', 'Light'),
        ('💨', 'Fan'),
        ('🔌', 'Smart Plug'),
        ('🌡️', 'Thermostat'),
    ]
    name = models.CharField(max_length=100, unique=True)
    icon = models.CharField(max_length=5, choices=ICON_CHOICES)
    description = models.TextField(blank=True)
    is_approved = models.BooleanField(default=False)

    # New fields for pin range
    pin_range_start = models.PositiveIntegerField(default=0)
    pin_range_end = models.PositiveIntegerField(default=0)
    
    @property
    def get_pin_range(self):
        return list(range(self.pin_range_start, self.pin_range_end + 1))


    def __str__(self):
        return self.name


# models.py
from django.contrib.auth.models import User
class ESPDevice(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)

    def __str__(self):
        return self.ip_address

class Device(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    device_type = models.ForeignKey(DeviceType, on_delete=models.SET_NULL, null=True)
    request = models.ForeignKey('DeviceRequest', on_delete=models.SET_NULL, null=True, blank=True)
    
    is_on = models.BooleanField(default=False)
    # pin_number = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(39)]) #we will use later
    pin_number = models.IntegerField(default=0)  # or whatever default makes sense

    esp_ip = models.GenericIPAddressField(blank=True, null=True, help_text="IP address of the ESP32 this device is connected to")
    location = models.CharField(max_length=100)
    # is_active = models.BooleanField(default=False)  # we renamed and comment it it instead of status to be is_active
    created_at = models.DateTimeField(auto_now_add=True)  # final correct version
    is_approved = models.BooleanField(default=False)


    def __str__(self):
        return f"{self.name} ({self.device_type})"

    class Meta:
        unique_together = ('esp_ip', 'pin_number')  # Prevent same pin on same ESP


class DeviceLog(models.Model):
    """
    Stores a log of ON/OFF actions taken on a device, including who performed it.
    """
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='logs')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=10, choices=[('ON', 'ON'), ('OFF', 'OFF')])
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.device.name} turned {self.action} at {self.timestamp}"


from datetime import datetime, date, timedelta
from django.db import models
from datetime import timedelta

class DeviceUsage(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='usages')
    time_on = models.DateTimeField()
    time_off = models.DateTimeField(null=True, blank=True)
    duration = models.DurationField(null=True, blank=True)  #  new field to store duration

    def duration_str(self):
        if self.duration:
            total_seconds = int(self.duration.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            return f"{hours}h {minutes}m"
        return "Running"

    def __str__(self):
        return f"{self.device.name} usage from {self.time_on} to {self.time_off or 'Running'}"


from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=15)

    def __str__(self):
        return self.user.username


class DeviceRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device_type = models.ForeignKey(DeviceType, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    name = models.CharField(max_length=100, blank=True)  # Add this line
    status = models.CharField(max_length=20, choices=[('Pending', 'Pending'), ('Approved', 'Approved'), ('Rejected', 'Rejected')], default='Pending')
    requested_at = models.DateTimeField(auto_now_add=True)
    assigned_pin = models.PositiveIntegerField(null=True, blank=True)
    approved_date = models.DateTimeField(null=True, blank=True)
    def __str__(self):
        return f"{self.name or 'Unnamed'} ({self.device_type.name})"



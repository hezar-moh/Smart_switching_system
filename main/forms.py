from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from .models import DeviceType, Device, UserProfile  # include UserProfile

# -------------------------------
#  Updated Register Form
# -------------------------------
class RegisterForm(UserCreationForm):
    phone_number = forms.CharField(max_length=15, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')  # exclude phone_number here

    def __init__(self, *args, **kwargs):
        super(RegisterForm, self).__init__(*args, **kwargs)
        for fieldname in self.fields:
            self.fields[fieldname].help_text = None

class DeviceTypeForm(forms.ModelForm):
    class Meta:
        model = DeviceType
        fields = ['name', 'icon', 'description', 'pin_range_start', 'pin_range_end']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'icon': forms.Select(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'pin_range_start': forms.NumberInput(attrs={'class': 'form-control'}),
            'pin_range_end': forms.NumberInput(attrs={'class': 'form-control'}),
        }
    def __init__(self, *args, **kwargs):
        super(DeviceTypeForm, self).__init__(*args, **kwargs)
        # Mark all fields as required
        for field in self.fields.values():
            field.required = True
    
    def clean(self):
        cleaned_data = super().clean()
        start = cleaned_data.get("pin_range_start")
        end = cleaned_data.get("pin_range_end")

        if start is not None and end is not None:
            if end <= start:
                self.add_error('pin_range_end', "Pin Range End must be greater than Pin Range Start.")
            
            # Get current instance id if available
            current_id = self.instance.id if self.instance and self.instance.id else None

            # Check overlap with other DeviceTypes
            overlapping = DeviceType.objects.exclude(id=current_id).filter(
                pin_range_start__lte=end,
                pin_range_end__gte=start
            )
            if overlapping.exists():
                raise ValidationError(
                    "Warning: Pin Range Overlap\n"
                    "Some device types have overlapping pin ranges. This may cause conflicts."
                )
            
        return cleaned_data
     


class AddDeviceForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = ['name', 'device_type', 'location']
        widgets = {
            'name': forms.TextInput(attrs={'placeholder': 'enter name of your device'}),
            'location': forms.TextInput(attrs={'placeholder': 'enter location of the device'}),
        }

from django import forms

class AssignPinForm(forms.Form):
    pin_number = forms.ChoiceField(label="Select Available Pin")

    def __init__(self, device_type, used_pins, *args, **kwargs):
        super().__init__(*args, **kwargs)
        available_pins = [
            pin for pin in range(device_type.pin_range_start, device_type.pin_range_end + 1)
            if pin not in used_pins
        ]
        self.fields['pin_number'].choices = [(pin, f"GPIO {pin}") for pin in available_pins]

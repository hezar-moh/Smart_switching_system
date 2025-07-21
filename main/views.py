from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.db.models import Count, Max
from django.utils.timezone import now, timedelta, localtime
from datetime import datetime
from django.http import HttpResponseForbidden
from .models import Device, DeviceLog, DeviceType, DeviceUsage
from .forms import RegisterForm, DeviceTypeForm, AddDeviceForm
from .models import UserProfile
from django.shortcuts import render, redirect
from django.contrib import messages
import os
from django.conf import settings

def home(request):
    return render(request, 'home.html')

def about(request):
    return render(request, 'about.html')

def support(request):
    return render(request, 'support.html')

def contact(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message_text = request.POST.get('message')

        if not name or not email or not message_text:
            messages.error(request, "Please fill all fields.")
            return redirect('contact')

        # Prepare the message content
        content = f"Name: {name}\nEmail: {email}\nMessage:\n{message_text}\n---\n"

        # Define the path where to save messages
        support_dir = os.path.join(settings.BASE_DIR, 'support_messages')
        os.makedirs(support_dir, exist_ok=True)  # create folder if not exists

        # Save each message in a file with timestamp
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"support_{timestamp}.txt"
        filepath = os.path.join(support_dir, filename)

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            messages.success(request, "Thank you! Your message has been saved.")
        except Exception as e:
            messages.error(request, f"Failed to save your message: {e}")

        return redirect('contact')

    return render(request, 'contact.html')


def register(request):
    form = RegisterForm()
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            phone_number = form.cleaned_data.get('phone_number')
            UserProfile.objects.create(user=user, phone_number=phone_number)

            login(request, user)
            messages.success(request, 'Account created successfully. Please log in.')
            return redirect('user_dashboard')
        else:
            messages.error(request, 'Please correct the errors below.')
    return render(request, 'register.html', {'form': form})

# Login View
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']  # use username here
        password = request.POST['password']
        role = request.POST.get('role')  # get the radio button value
        
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            if role == 'admin':
                if user.is_superuser:
                    return redirect('admin_dashboard')
                else:
                    logout(request)
                    messages.error(request, 'You are not authorized as admin.')
            elif role == 'user':
                if not user.is_superuser:
                    return redirect('user_dashboard')  # create this view
                else:
                    logout(request)
                    messages.error(request, 'Admins cannot log in as regular users.')
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'login.html')


# @login_required
def logout_view(request):
    logout(request)
    return redirect('login')

# Admin Dashboard
# @login_required
def admin_dashboard(request):
    if not request.user.is_superuser:
        return HttpResponseForbidden("You are not authorized to view this page.")
    
    
    total_users = User.objects.filter(is_superuser=False).count()
    recent_time = now() - timedelta(hours=24)
    active_user_ids = DeviceLog.objects.filter(timestamp__gte=recent_time).values_list('device__owner', flat=True).distinct()
    active_users = User.objects.filter(id__in=active_user_ids).count()
    total_devices = Device.objects.count()
    online_devices = Device.objects.filter(is_on=True).count()
    recent_logs = (
        DeviceLog.objects
        .select_related('device__owner')
        .values('device__owner__id', 'device__owner__username', 'device__owner__email')
        .annotate(
            device_count=Count('device__id', distinct=True),
            last_active=Max('timestamp')
        )
        .order_by('-last_active')[:5]
    )
    context = {
        'total_users': total_users,
        'active_users': active_users,
        'total_devices': total_devices,
        'online_devices': online_devices,
        'recent_users': recent_logs,
    }
    return render(request, 'admin_dashboard.html', context)

# User Management
# @login_required
def manage_users(request):
    users = User.objects.filter(is_superuser=False).annotate(device_count=Count('device'))
    form = RegisterForm()
    return render(request, 'manage_user.html', {'users': users, 'form': form})

# @login_required
def delete_user(request, user_id):
    if request.method == 'POST':
        user = get_object_or_404(User, id=user_id)
        user.delete()
    return redirect('manage_users')

# @login_required
def add_user(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('manage_users')
    else:
        form = RegisterForm()
    return render(request, 'manage_user.html', {'form': form})

# Device Type Management
# @login_required
def device_type_view(request):
    device_types = DeviceType.objects.all()
    if request.method == 'POST':
        form = DeviceTypeForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('device_types')
    else:
        form = DeviceTypeForm()
    return render(request, 'device_types.html', {'device_types': device_types, 'form': form})

# @login_required
def delete_device_type(request, pk):
    device_type = get_object_or_404(DeviceType, pk=pk)
    device_type.delete()
    return redirect('device_types')

# @login_required
def edit_device_type(request, pk):
    device_type = get_object_or_404(DeviceType, pk=pk)
    if request.method == 'POST':
        form = DeviceTypeForm(request.POST, instance=device_type)
        if form.is_valid():
            form.save()
            return redirect('device_types')
    else:
        form = DeviceTypeForm(instance=device_type)
    return render(request, 'edit_device_type.html', {'form': form, 'device_type': device_type})

# Utility to determine greeting (morning, afternoon, evening)
def get_greeting_time():
    current_hour = now().hour
    if current_hour < 12:
        return "morning"
    elif current_hour < 18:
        return "afternoon"
    else:
        return "evening"

# @login_required
def user_dashboard(request):
    from collections import Counter

    devices = Device.objects.filter(owner=request.user, is_approved=True)
    device_types = DeviceType.objects.all()
    device_requests = DeviceRequest.objects.filter(user=request.user, status='Pending')  #  only pending

    greeting_time = get_greeting_time()
    
    approved_device_count = Counter()
    for device in devices:
        approved_device_count[device.device_type.id] += 1

    pending_devices_expanded = []
    for req in device_requests:
        approved_count = approved_device_count.get(req.device_type.id, 0)
        remaining = req.quantity - approved_count
        for i in range(1, remaining + 1):
            pending_devices_expanded.append({
                'name': f"{req.device_type.name} {approved_count + i}",
                'device_type': req.device_type,
                'status': 'Pending',
            })

    return render(request, 'user_dashboard.html', {
        'devices': devices,
        'device_types': device_types,
        'pending_devices': pending_devices_expanded,
        'greeting_time': greeting_time,
    })


# @login_required
from .models import Device, DeviceType, DeviceRequest
from django.shortcuts import render, redirect

from django.utils.text import slugify

from django.shortcuts import get_object_or_404, redirect, render

def manage_devices(request):
    devices = Device.objects.filter(owner=request.user)
    device_requests = DeviceRequest.objects.filter(user=request.user, status='Pending')

    device_types = DeviceType.objects.all()

    if request.method == 'POST':
        device_type_id = request.POST.get('device_type')
        quantity = request.POST.get('quantity')

        if device_type_id and quantity and quantity.isdigit():
            device_type = get_object_or_404(DeviceType, id=device_type_id)
            quantity = int(quantity)

            # Check for existing pending request
            existing_request = DeviceRequest.objects.filter(
                user=request.user, device_type=device_type, status='Pending'
            ).first()

            if existing_request:
                # Update quantity
                existing_request.quantity += quantity
                existing_request.save()
            else:
                # Create new request
                DeviceRequest.objects.create(
                    user=request.user,
                    device_type=device_type,
                    quantity=quantity,
                    status='Pending'
                )
        return redirect('manage_devices')

    return render(request, 'manage_devices.html', {
        'devices': devices,
        'device_requests': device_requests,
        'device_types': device_types,
    })
    
from django.shortcuts import get_object_or_404

def delete_request(request, req_id):
    req = get_object_or_404(DeviceRequest, id=req_id, user=request.user)
    if req.status == 'Pending':
        if req.quantity > 1:
            req.quantity -= 1
            req.save()
        else:
            req.delete()
    return redirect('manage_devices')


from django.shortcuts import get_object_or_404, redirect, render

def edit_device_name(request, device_id):
    device = get_object_or_404(Device, id=device_id, owner=request.user)

    if not device.is_approved:
        # Not approved yet: deny editing
        return redirect('manage_devices')

    if request.method == 'POST':
        new_name = request.POST.get('name')
        if new_name:
            device.name = new_name
            device.save()
            return redirect('manage_devices')

    return render(request, 'edit_device_name.html', {'device': device})

from django.contrib import messages

def delete_device(request, device_id):
    device = get_object_or_404(Device, id=device_id, owner=request.user)

    # Check if the device is part of an approved request
    approved = DeviceRequest.objects.filter(user=request.user, device_type=device.device_type, status='Approved').exists()

    if approved:
        messages.error(request, "You cannot delete an approved device. Please contact the admin.")
        return redirect('manage_devices')

    device.delete()
    messages.success(request, "Device deleted successfully.")
    return redirect('manage_devices')

# @login_required

from django.shortcuts import get_object_or_404, render
from django.contrib.auth.decorators import login_required
from .models import Device, DeviceUsage  # import DeviceUsage

# @login_required
def device_detail(request, device_id):
    device = get_object_or_404(Device, id=device_id, owner=request.user)
    usage_history = DeviceUsage.objects.filter(device=device).order_by('-time_on')
    
    return render(request, 'device_detail.html', {
        'device': device,
        'usage_history': usage_history,
    })

from django.utils.timezone import localtime
from django.contrib import messages
from django.shortcuts import redirect, get_object_or_404
from datetime import timedelta
import requests

from .models import Device, DeviceLog, DeviceUsage

# @login_required
def toggle_device(request, device_id):
    device = get_object_or_404(Device, id=device_id, owner=request.user)

    if request.method == 'POST':
        new_state = not device.is_on
        action = 'on' if new_state else 'off'
        pin = device.pin_number
        esp_ip = device.esp_ip

        if esp_ip:
            try:
                url = f"http://{esp_ip}/control?pin={pin}&state={action}"
                response = requests.get(url, timeout=2)

                if response.status_code != 200:
                    messages.error(request, f"ESP32 error: {response.text}")
                    return redirect('user_dashboard')

            except requests.exceptions.RequestException:
                messages.error(request, "ESP32 not reachable. Please check the device connection and try again.")
                return redirect('user_dashboard')
        else:
            messages.error(request, "ESP32 IP not set for this device.")
            return redirect('user_dashboard')
   
        device.is_on = new_state
        device.save()
       
        DeviceLog.objects.create(
            device=device,
            user=request.user,
            action='ON' if new_state else 'OFF'
        )
        now = localtime()

        if new_state:
            # Turned ON — Start new usage
            DeviceUsage.objects.create(
                device=device,
                time_on=now
            )
        else:
            # Turned OFF — Complete latest usage
            try:
                usage = DeviceUsage.objects.filter(
                    device=device, time_off__isnull=True
                ).latest('time_on')
                usage.time_off = now
                usage.duration = usage.time_off - usage.time_on
                usage.save()
            except DeviceUsage.DoesNotExist:
                pass

        messages.success(request, f"{device.name} turned {'ON' if new_state else 'OFF'}.")

    return redirect('user_dashboard')

# @login_required
def toggle_user_status(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_active = not user.is_active
    user.save()
    return redirect('manage_users')


# @login_required
def device_logs(request):
    user = request.user
    # Only fetch actual approved devices
    devices = Device.objects.filter(owner=user).order_by('name')

    device_id = request.GET.get('device')
    # Only fetch logs for approved devices
    usages = DeviceUsage.objects.filter(device__in=devices)

    if device_id:
        usages = usages.filter(device_id=device_id)
        
    usages = usages.order_by('-time_on')[:100]
    context = {
        'devices': devices,
        'logs': usages,
    }
    return render(request, 'device_logs.html', context)



# views.py
from collections import defaultdict
from django.shortcuts import render
from .models import DeviceRequest, DeviceType, Device

from collections import defaultdict
from django.shortcuts import render, get_object_or_404
from .models import User, DeviceRequest, DeviceType, Device, ESPDevice  # Make sure ESPDevice is imported
from django.db.models import Count

def admin_device_request_detail(request, user_id):
    user = get_object_or_404(User, id=user_id)
    pending_requests = DeviceRequest.objects.filter(user=user, status='Pending')

    grouped_requests = []
    for req in pending_requests:
        expanded_devices = [{'device_type': req.device_type, 'index': i, 'request_id': req.id} for i in range(1, req.quantity + 1)]
        grouped_requests.append({
            'request': req,
            'devices': expanded_devices
        })

    device_types = DeviceType.objects.all()

    def get_available_pins_for_type(device_type):
        used_pins = set(Device.objects.filter(device_type=device_type).values_list('pin_number', flat=True))
        all_pins = set(range(device_type.pin_range_start, device_type.pin_range_end + 1))
        return sorted(list(all_pins - used_pins))

    device_type_to_available_pins = {
        dt.id: get_available_pins_for_type(dt) for dt in device_types
    }

    # NEW: show only unused ESP IPs
    used_ips = Device.objects.values_list('esp_ip', flat=True).distinct()
    esp_devices = ESPDevice.objects.exclude(ip_address__in=used_ips)

    context = {
        'user': user,
        'requests': grouped_requests,
        'device_type_to_available_pins': device_type_to_available_pins,
        'esp_devices': esp_devices,
    }

    return render(request, 'admin_device_request_detail.html', context)

from collections import defaultdict

def admin_device_request_detail(request, user_id):
    user = User.objects.get(id=user_id)
    pending_requests = DeviceRequest.objects.filter(user=user, status='Pending')

    grouped_requests = []

    for req in pending_requests:
        expanded_devices = [{'device_type': req.device_type, 'index': i, 'request_id': req.id} for i in range(1, req.quantity + 1)]
        grouped_requests.append({
            'request': req,
            'devices': expanded_devices
        })

    device_types = DeviceType.objects.all()

    def get_available_pins_for_type(device_type):
        used_pins = set(Device.objects.filter(device_type=device_type).values_list('pin_number', flat=True))
        all_pins = set(range(device_type.pin_range_start, device_type.pin_range_end + 1))
        return sorted(list(all_pins - used_pins))

    device_type_to_available_pins = {dt.id: get_available_pins_for_type(dt) for dt in device_types}
    
    esp_devices = ESPDevice.objects.filter()
    context = {
        'user': user,
        'requests': grouped_requests,
        'device_type_to_available_pins': device_type_to_available_pins,
        
        'esp_devices': esp_devices,  #  pass to template
    }

    return render(request, 'admin_device_request_detail.html', context)


    # Helper function to get available pins for a device type
    def get_available_pins_for_type(device_type):
        # Get all used pins for this device type
        used_pins = set(Device.objects.filter(device_type=device_type).values_list('pin_number', flat=True))
        # Generate all possible pins in the range
        all_pins = set(range(device_type.pin_range_start, device_type.pin_range_end + 1))
        # Return pins that are not used
        return sorted(list(all_pins - used_pins))

    device_type_to_available_pins = {
        dt.id: get_available_pins_for_type(dt)
        for dt in device_types
    }

    context = {
        'requests': grouped_requests,
        'device_type_pins': {
    f"{dt.id}": get_available_pins_for_type(dt) for dt in device_types
}

    }

    return render(request, 'admin_device_requests.html', context)
from collections import defaultdict
from django.utils import timezone
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from .models import DeviceRequest, Device
from collections import defaultdict
from django.shortcuts import render
from django.utils import timezone
from .models import DeviceRequest, Device

from collections import defaultdict
from django.shortcuts import render
from django.utils import timezone
from .models import DeviceRequest, Device

from collections import defaultdict
from django.shortcuts import render
from .models import DeviceRequest, Device

def approved_requests_summary(request):
    approved_requests = DeviceRequest.objects.filter(status='Approved') \
        .select_related('user', 'device_type') \
        .order_by('user', '-approved_date')

    approved_data = defaultdict(list)

    for req in approved_requests:
        assigned_devices = Device.objects.filter(request=req).order_by('pin_number')

        if assigned_devices.exists():
            approved_data[req.user].append({
                'device_type': req.device_type.name,
                'request_date': req.requested_at,
                'approved_date': req.approved_date,
                'devices': list(assigned_devices),
            })

    return render(request, 'approved_requests_summary.html', {
        'approved_data': dict(approved_data)
    })



# @staff_member_required
def admin_delete_device(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    device.delete()
    messages.success(request, f"Device '{device.name}' deleted successfully.")
    return redirect('approved_requests_summary')



from .models import DeviceRequest, Device, DeviceType, UserProfile
from django.contrib.auth.models import User
from django.shortcuts import render, get_object_or_404, redirect
from django.forms import Form, ChoiceField

# Dynamic form per device
class AssignPinForm(Form):
    def __init__(self, device_type, used_pins, *args, **kwargs):
        super().__init__(*args, **kwargs)
        available_pins = [
            pin for pin in range(device_type.pin_range_start, device_type.pin_range_end + 1)
            if pin not in used_pins
        ]
        self.fields['pin_number'] = ChoiceField(choices=[(p, f'Pin {p}') for p in available_pins])

# Admin requests overview
def admin_device_requests(request):
    requests = DeviceRequest.objects.filter(status='Pending').select_related('user', 'device_type')
    users = {}
    for r in requests:
        users.setdefault(r.user, []).append(r)
    return render(request, 'admin/device_requests.html', {'users': users})

# main/views.py
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import user_passes_test
from collections import defaultdict
from .models import DeviceRequest

def is_admin(user):
    return user.is_staff  # Or your own admin check logic

# @user_passes_test(is_admin)
from collections import defaultdict
from django.shortcuts import render
from .models import DeviceRequest

from collections import defaultdict
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.utils import timezone
from django.contrib.auth.models import User

from .models import DeviceRequest, Device, DeviceType
from .forms import AssignPinForm


def admin_device_requests(request):
    #  Only pending requests
    pending_reqs = DeviceRequest.objects.filter(status='Pending').select_related('device_type', 'user')

    requests_by_user = defaultdict(list)
    for req in pending_reqs:
        requests_by_user[req.user].append(req)

    used_pins = set(Device.objects.values_list('pin_number', flat=True))

    device_type_to_available_pins = defaultdict(list)
    for device in Device.objects.all():
        if device.pin_number not in used_pins:
            device_type_to_available_pins[device.device_type_id].append(device.pin_number)

    context = {
        'requests': dict(requests_by_user),
        'used_pins': used_pins,
        'device_type_to_available_pins': dict(device_type_to_available_pins),
    }
    return render(request, 'admin_device_requests.html', context)


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.utils import timezone
from .models import User, DeviceRequest, Device, DeviceType
from .forms import AssignPinForm

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.utils import timezone
from .models import User, DeviceRequest, Device, DeviceType
from .forms import AssignPinForm

def admin_approve_user_request(request, user_id):
    user = get_object_or_404(User, id=user_id)
    requests = DeviceRequest.objects.filter(user=user, status='Pending')
    formsets = {}
    device_type_to_available_pins = {}

    if request.method == 'POST':
        #  Get the selected ESP IP once for the entire user
        esp_ip = request.POST.get('esp_ip')
        if not esp_ip:
            messages.error(request, "Please select an ESP IP.")
            return redirect('admin_device_request_detail', user_id=user_id)

        all_valid = True

        for req in requests:
            device_type = req.device_type
            used_pins = list(Device.objects.filter(device_type=device_type).values_list('pin_number', flat=True))
            formset = []

            for i in range(req.quantity):
                form = AssignPinForm(device_type, used_pins, request.POST, prefix=f"{req.id}_{i}")
                formset.append(form)

                if form.is_valid():
                    used_pins.append(int(form.cleaned_data['pin_number']))
                else:
                    all_valid = False

            formsets[req] = formset

        if all_valid:
            for req, forms in formsets.items():
                for idx, form in enumerate(forms):
                    pin = int(form.cleaned_data['pin_number'])

                    #  Create device using the selected ESP IP
                    Device.objects.create(
                        owner=user,
                        name=f"{req.device_type.name} {idx+1}",
                        device_type=req.device_type,
                        pin_number=pin,
                        esp_ip=esp_ip,
                        location='',
                        is_on=False,
                        is_approved=True,
                        request=req
                    )

                req.status = 'Approved'
                req.approved_date = timezone.now()
                req.save()

            messages.success(request, f"{user.username}'s devices were successfully approved.")
            return redirect('approved_requests_summary')  # Or change as needed

    else:
        for req in requests:
            used_pins = list(Device.objects.filter(device_type=req.device_type).values_list('pin_number', flat=True))
            formset = [AssignPinForm(req.device_type, used_pins, prefix=f"{req.id}_{i}") for i in range(req.quantity)]
            formsets[req] = formset

    # Show available pins per device type
    device_types = DeviceType.objects.all()
    for dt in device_types:
        all_pins = set(range(dt.pin_range_start, dt.pin_range_end + 1))
        used_pins = set(Device.objects.filter(device_type=dt).values_list('pin_number', flat=True))
        device_type_to_available_pins[dt.id] = sorted(all_pins - used_pins)

    return render(request, 'admin_device_request_detail.html', {
        'user': user,
        'requests': [{'request': req, 'devices': [
            {'device_type': req.device_type, 'index': i + 1, 'request_id': req.id}
            for i in range(req.quantity)
        ]} for req in requests],
        'device_type_to_available_pins': device_type_to_available_pins,
        'formsets': formsets,
        #  Don't forget to pass esp_devices to the template
        'esp_devices': ESPDevice.objects.all(),
    })

from django.shortcuts import get_object_or_404, redirect
from .models import DeviceRequest

def reject_device_request(request, req_id):
    req = get_object_or_404(DeviceRequest, id=req_id)
    req.status = 'Rejected'
    req.save()
    return redirect('admin_device_requests')  # Or redirect to grouped view if you're grouping by user
from django.shortcuts import get_object_or_404, redirect
from .models import DeviceRequest, Device
from django.contrib.auth.models import User

def reject_all_requests_by_user(request, user_id):
    user = get_object_or_404(User, id=user_id)

    # Step 1: Reject all pending requests
    DeviceRequest.objects.filter(user=user, status='Pending').update(status='Rejected')

    # Step 2: Delete devices that are not yet approved
    # (this assumes only "approved" devices are valid for keeping)
    Device.objects.filter(owner=user, is_approved=False).delete()

    return redirect('admin_device_requests')


#view for creating ip for whic will used per user
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import user_passes_test
from .models import ESPDevice

def admin_required(user):
    return user.is_superuser or user.is_staff

@user_passes_test(admin_required)
def manage_esp_devices(request):  #here is where we used to add ip addressses
    if request.method == 'POST':
        ip = request.POST.get('ip_address')
        if ip:
            ESPDevice.objects.get_or_create(ip_address=ip)
        return redirect('manage_esp_devices')

    devices = ESPDevice.objects.all()
    return render(request, 'manage_esp_devices.html', {'devices': devices})

@user_passes_test(admin_required)
def delete_esp_device(request, device_id):
    esp = get_object_or_404(ESPDevice, id=device_id)
    esp.delete()
    messages.success(request, f"ESP Device {esp.ip_address} deleted successfully.")
    return redirect('manage_esp_devices')


@user_passes_test(admin_required)
def edit_esp_device(request, device_id):
    esp = get_object_or_404(ESPDevice, id=device_id)

    if request.method == 'POST':
        new_ip = request.POST.get('new_ip')
        if new_ip:
            esp.ip_address = new_ip
            esp.save()
            messages.success(request, "ESP IP updated successfully.")
        return redirect('manage_esp_devices')

    return render(request, 'edit_esp_device.html', {'esp': esp})



from django.urls import path
from . import views


urlpatterns = [
    path('', views.home, name='home'),
    path('about/', views.about, name='about'),
    path('support/', views.support, name='support'),
    path('contact/', views.contact, name='contact'),
    
    path('register/', views.register, name ="register"),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('admin_dashboard', views.admin_dashboard, name='admin_dashboard'),
    path('dashboard/manage-users/', views.manage_users, name='manage_users'),
    path('dashboard/user/add/', views.add_user, name='add_user'),
    path('dashboard/user/toggle/<int:user_id>/', views.toggle_user_status, name='toggle_user_status'),
    path('dashboard/user/delete/<int:user_id>/', views.delete_user, name='delete_user'),
    path('device-types/', views.device_type_view, name='device_types'),
    path('device_types/delete/<int:pk>/', views.delete_device_type, name='delete_device_type'),
    path('device_types/edit/<int:pk>/', views.edit_device_type, name='edit_device_type'),
    
    path('dashboard/', views.user_dashboard, name='user_dashboard'),
    path('toggle-device/<int:device_id>/', views.toggle_device, name='toggle_device'),
    path('manage-devices/', views.manage_devices, name='manage_devices'),

    path('devices/delete/<int:device_id>/', views.delete_device, name='delete_device'),
    path('approved-summary/delete-device/<int:device_id>/', views.admin_delete_device, name='admin_delete_device'),#admin to delete approved users



    path('delete-request/<int:req_id>/', views.delete_request, name='delete_request'),
    path('edit-device-name/<int:device_id>/', views.edit_device_name, name='edit_device_name'),


    
    path('manage-device/<int:device_id>/', views.device_detail, name='device_detail'),
    
    path('device_logs/',views.device_logs, name='device_logs'),


    path('dashboard-admin/device-requests/', views.admin_device_requests, name='admin_device_requests'),
    path('dashboard-admin/device-requests/<int:user_id>/', views.admin_device_request_detail, name='admin_device_request_detail'),

    path('dashboard-admin/requests/approve/<int:user_id>/', views.admin_approve_user_request, name='admin_approve_user_request'),

    path('dashboard-admin/approved-requests/', views.approved_requests_summary, name='approved_requests_summary'),

    path('dashboard-admin/requests/reject/<int:req_id>/', views.reject_device_request, name='reject_device_request'),
    path('dashboard-admin/requests/<int:user_id>/reject/', views.reject_all_requests_by_user, name='reject_all_requests_by_user'),

    path('dashboard-admin/device-types/', views.device_type_view, name='device_types'),
    
    path('dashboard-admin/esp-devices/', views.manage_esp_devices, name='manage_esp_devices'),
        
    path('dashboard-admin/esp-devices/delete/<int:device_id>/', views.delete_esp_device, name='delete_esp_device'),
    path('dashboard-admin/esp-devices/edit/<int:device_id>/', views.edit_esp_device, name='edit_esp_device'),
] 
"""
Django admin configuration for Location Management.

This module provides admin interfaces for locations, floor plans,
zones, and device location mappings.
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe

# Note: These models will be implemented in Phase 3
# For now, we're creating placeholder admin classes that can be uncommented
# when the actual models are created.

"""
Placeholder admin classes for Location models.
Uncomment and modify these when implementing Phase 3 Location Management.

from apps.locations.models import (
    Location, FloorPlan, Zone, Device, DeviceLocationMapping
)


class DeviceLocationMappingInline(admin.TabularInline):
    model = DeviceLocationMapping
    extra = 0
    fields = ('device', 'x_coordinate', 'y_coordinate', 'floor', 'zone')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(Location)
class LocationAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'location_type', 'parent', 'location_code',
        'is_active', 'device_count', 'created_at'
    )

    list_filter = (
        'location_type', 'is_active', 'created_at', 'parent'
    )

    search_fields = (
        'name', 'location_code', 'description', 'address'
    )

    ordering = ('name',)

    readonly_fields = ('created_at', 'updated_at', 'hierarchy_path')

    fieldsets = (
        (None, {
            'fields': ('name', 'location_code', 'location_type', 'parent')
        }),
        ('Details', {
            'fields': ('description', 'address', 'is_active')
        }),
        ('Geographic Information', {
            'fields': ('latitude', 'longitude', 'timezone'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
        ('Hierarchy Information', {
            'fields': ('hierarchy_path',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    inlines = [DeviceLocationMappingInline]

    def device_count(self, obj):
        count = obj.devices.count()
        if count > 0:
            url = reverse('admin:locations_device_changelist')
            return format_html(
                '<a href="{}?location__id={}">{} devices</a>',
                url, obj.id, count
            )
        return count
    device_count.short_description = 'Devices'

    def hierarchy_path(self, obj):
        return " → ".join(obj.get_hierarchy_path())
    hierarchy_path.short_description = 'Hierarchy Path'


@admin.register(FloorPlan)
class FloorPlanAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'location', 'version', 'is_active',
        'scale_factor', 'created_at'
    )

    list_filter = (
        'is_active', 'version', 'created_at', 'location__location_type'
    )

    search_fields = (
        'name', 'description', 'location__name'
    )

    ordering = ('-created_at',)

    readonly_fields = ('created_at', 'updated_at', 'file_size', 'image_dimensions')

    fieldsets = (
        (None, {
            'fields': ('name', 'location', 'floor_plan_file', 'version')
        }),
        ('Configuration', {
            'fields': ('scale_factor', 'origin_x', 'origin_y', 'rotation', 'is_active')
        }),
        ('Details', {
            'fields': ('description',)
        }),
        ('File Information', {
            'fields': ('file_size', 'image_dimensions'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def file_size(self, obj):
        if obj.floor_plan_file:
            size = obj.floor_plan_file.size
            if size < 1024:
                return f"{size} bytes"
            elif size < 1024 * 1024:
                return f"{size / 1024:.1f} KB"
            else:
                return f"{size / (1024 * 1024):.1f} MB"
        return "No file"
    file_size.short_description = 'File Size'

    def image_dimensions(self, obj):
        if obj.floor_plan_file:
            try:
                from PIL import Image
                image = Image.open(obj.floor_plan_file.path)
                return f"{image.width} × {image.height} pixels"
            except:
                return "Unknown"
        return "No file"
    image_dimensions.short_description = 'Dimensions'


@admin.register(Zone)
class ZoneAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'zone_type', 'floor_plan', 'location',
        'is_active', 'device_count', 'created_at'
    )

    list_filter = (
        'zone_type', 'is_active', 'created_at', 'floor_plan__location'
    )

    search_fields = (
        'name', 'description', 'floor_plan__name', 'location__name'
    )

    ordering = ('name',)

    readonly_fields = ('created_at', 'updated_at', 'area_calculation')

    fieldsets = (
        (None, {
            'fields': ('name', 'zone_type', 'floor_plan', 'location')
        }),
        ('Geometry', {
            'fields': ('coordinates', 'area_calculation')
        }),
        ('Configuration', {
            'fields': ('access_level', 'is_active', 'color')
        }),
        ('Details', {
            'fields': ('description', 'metadata')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def device_count(self, obj):
        count = obj.devices.count()
        if count > 0:
            return f"{count} devices"
        return "No devices"
    device_count.short_description = 'Devices'

    def area_calculation(self, obj):
        # Calculate area from polygon coordinates
        # This would be implemented based on the coordinate system
        return "Area calculation to be implemented"
    area_calculation.short_description = 'Calculated Area'


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'device_type', 'device_id', 'current_location',
        'status', 'is_active', 'last_seen'
    )

    list_filter = (
        'device_type', 'status', 'is_active', 'created_at', 'last_seen'
    )

    search_fields = (
        'name', 'device_id', 'description', 'manufacturer', 'model'
    )

    ordering = ('name',)

    readonly_fields = ('created_at', 'updated_at', 'last_seen')

    fieldsets = (
        (None, {
            'fields': ('name', 'device_id', 'device_type', 'is_active')
        }),
        ('Hardware Information', {
            'fields': ('manufacturer', 'model', 'serial_number', 'firmware_version')
        }),
        ('Status', {
            'fields': ('status', 'last_seen', 'health_status')
        }),
        ('Configuration', {
            'fields': ('configuration', 'metadata')
        }),
        ('Details', {
            'fields': ('description',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def current_location(self, obj):
        mapping = obj.location_mappings.filter(is_active=True).first()
        if mapping:
            return mapping.location.name
        return "No location assigned"
    current_location.short_description = 'Current Location'


@admin.register(DeviceLocationMapping)
class DeviceLocationMappingAdmin(admin.ModelAdmin):
    list_display = (
        'device', 'location', 'floor', 'zone',
        'x_coordinate', 'y_coordinate', 'is_active', 'created_at'
    )

    list_filter = (
        'is_active', 'created_at', 'location', 'floor', 'zone'
    )

    search_fields = (
        'device__name', 'device__device_id', 'location__name',
        'floor__name', 'zone__name'
    )

    ordering = ('-created_at',)

    readonly_fields = ('created_at', 'updated_at')

    fieldsets = (
        (None, {
            'fields': ('device', 'location', 'is_active')
        }),
        ('Positioning', {
            'fields': ('floor', 'zone', 'x_coordinate', 'y_coordinate')
        }),
        ('Details', {
            'fields': ('notes', 'metadata')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
"""


# Placeholder admin registration
# These will be uncommented when the actual models are implemented in Phase 3

# Example of how to register when models are ready:
# admin.site.register(Location, LocationAdmin)
# admin.site.register(FloorPlan, FloorPlanAdmin)
# admin.site.register(Zone, ZoneAdmin)
# admin.site.register(Device, DeviceAdmin)
# admin.site.register(DeviceLocationMapping, DeviceLocationMappingAdmin)

# For now, we'll create a simple placeholder
class LocationPlaceholderAdmin(admin.ModelAdmin):
    """
    Placeholder admin for locations.
    This will be replaced with actual location models in Phase 3.
    """

    def has_module_permission(self, request):
        """Hide this from admin until Phase 3 is implemented."""
        return False


# Temporary message for admin users
from django.contrib import messages
from django.contrib.admin import AdminSite


def add_location_admin_message():
    """Add a message about location management coming in Phase 3."""
    pass  # This will be implemented when we add location models
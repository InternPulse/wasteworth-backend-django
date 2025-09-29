"""
Temporary solution for handling missing django_rq.
This will be used to conditionally add django_rq to INSTALLED_APPS.
"""

# Try to import django_rq
try:
    import django_rq
    DJANGO_RQ_AVAILABLE = True
except ImportError:
    DJANGO_RQ_AVAILABLE = False
    
def get_installed_apps_extension():
    """
    Returns additional apps to add to INSTALLED_APPS based on what's available.
    """
    extension = []
    
    if DJANGO_RQ_AVAILABLE:
        extension.append('django_rq')
        
    return extension
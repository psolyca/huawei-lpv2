
from functools import wraps
from typing import Optional, Callable

SERVICES = None

def load_services():
    # To avoid circular import...
    from .device_config import DeviceConfig
    from .fitness import Fitness
    from .locale_config import LocaleConfig
    from .notification import Notification

    global SERVICES

    SERVICES = (
        DeviceConfig,
        Fitness,
        LocaleConfig,
        Notification,
    )

# Thanks to https://mgarod.medium.com/dynamically-add-a-method-to-a-class-in-python-c49204b85bd6
def add_method(cls: object):
    def decorator(func):
        @wraps(func) 
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        setattr(cls, 'process', wrapper)
        return func
    return decorator


def get_service(service_id: int) -> object:
    load_services()
    for cls in SERVICES:
        if cls.id == service_id:
            return cls


def get_command(service: object, command_id: int) -> object:
    for cls in dir(service):
        obj = getattr(service, cls)
        if isinstance(obj, type) and cls != '__class__':
            if obj.id == command_id:
                return obj
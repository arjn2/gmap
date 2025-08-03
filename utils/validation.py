# utils/validation.py - Decorators for validation

import functools
import socket
import ipaddress

def validate_ip(func):
    """Decorator to validate IP input."""
    @functools.wraps(func)
    def wrapper(ip, *args, **kwargs):
        try:
            ipaddress.ip_address(ip)
            return func(ip, *args, **kwargs)
        except ValueError:
            print(f"Invalid IP: {ip}")
            return False
    return wrapper

def timeout_handler(seconds):
    """Decorator for timeouts (simplified)."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Simplified timeout (use signal/alarm in production)
            try:
                return func(*args, **kwargs)
            except Exception as e:
                print(f"Timeout: {e}")
                return None
        return wrapper
    return decorator

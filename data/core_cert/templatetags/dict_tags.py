from django import template

register = template.Library()

@register.filter
def dict_get(value, arg):
    if hasattr(value, 'get'):
        return value.get(arg)
    return None

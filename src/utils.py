def get_platform_status():
    """Return the current status of the Cloud Security Intelligence Platform.

    Returns:
        str: A human-readable platform status message.    
    """
    return "Cloud Security Intelligence Platform is running!"

def format_resource_name(resource_name: str) -> str:
    """Format a cloud resource name for display.
    
    Args:
        resource_name: Name of the cloud resource.
        
    Returns:
        str: The formatted resource name.
    """
    return resource_name.upper()
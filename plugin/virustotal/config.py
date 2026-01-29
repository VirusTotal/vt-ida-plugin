
# VT-IDA plugin global configuration file

API_KEY = ''  # Mandatory for CodeInsight
DEBUG = False

try:
    import ida_settings

    vt_api_key = ida_settings.get_current_plugin_setting("api_key")
    if vt_api_key:
        API_KEY = vt_api_key

    vt_debug = ida_settings.get_current_plugin_setting("debug")
    if vt_debug is not None:
        DEBUG = bool(vt_debug)
except:
    pass
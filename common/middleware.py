class CacheHeaderMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Cache-Control'] = (
            'no-cache="Set-Cookie, Set-Cookie2", no-store, must-revalidate'
        )
        response['Pragma'] = 'no-cache'
        return response


class SecurityHeaderMiddleware(object):
    """
    Middleware to add/normalize security headers and strip potentially
    identifying headers like 'Server' from responses to avoid information
    leakage about the server implementation.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Remove Server header if present to avoid information disclosure
        try:
            if 'Server' in response:
                del response['Server']
        except Exception:
            pass

        # Always set protective security headers. Do not rely on untrusted
        # request attributes (User-Agent, REMOTE_ADDR) to enable/disable them.
        csp_value = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'"
        if not response.get('Content-Security-Policy'):
            response['Content-Security-Policy'] = csp_value
        response.setdefault('X-Content-Type-Options', 'nosniff')
        response.setdefault('X-XSS-Protection', '1; mode=block')

        return response

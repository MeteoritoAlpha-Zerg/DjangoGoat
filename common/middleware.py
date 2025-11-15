
class CacheHeaderMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Cache-Control'] = (
            'no-cache="Set-Cookie, Set-Cookie2", no-store, must-revalidate'
        )
        # Add comprehensive Content Security Policy header with proper fallbacks
        # All directives have proper fallback to default-src where appropriate
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "  # Removed 'unsafe-inline'
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'; "  # No plugins allowed
            "media-src 'self'; "
            "child-src 'self';"
        )
        return response

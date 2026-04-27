class CacheHeaderMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Cache-Control'] = (
            'no-cache="Set-Cookie, Set-Cookie2", no-store, must-revalidate'
        )
        response['Pragma'] = 'no-cache'

        # Add a default Content Security Policy (CSP) header to reduce XSS
        # attack surface. This is a conservative policy that allows only same-origin
        # resources and disallows plugins. Adjust as required by the application.
        try:
            csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'"
            response.setdefault('Content-Security-Policy', csp)
        except Exception:
            # If the response object doesn't support dict-like methods, ignore
            pass

        # Remove server-identifying headers if present to reduce information leakage
        try:
            # HttpResponse behaves like a dict for headers
            response.pop('Server', None)
        except Exception:
            try:
                # Some Django versions expose headers via 'headers' mapping
                if hasattr(response, 'headers'):
                    response.headers.pop('Server', None)
            except Exception:
                pass
        try:
            response.pop('X-Powered-By', None)
        except Exception:
            if hasattr(response, 'headers'):
                try:
                    response.headers.pop('X-Powered-By', None)
                except Exception:
                    pass
        return response

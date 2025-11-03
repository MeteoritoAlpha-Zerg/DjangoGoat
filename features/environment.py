import os
import subprocess
from shutil import which

from time import sleep

from behave import (
    fixture,
    use_fixture,
)

import django
from django.core.management import call_command

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service as FirefoxService

from zapv2 import ZAPv2


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BASE_URL = os.environ.get('DJANGO_GOAT_BASE_URL', 'http://localhost:8000')


def _safe_int(value, default=-1):
    """
    Safely convert ZAP API responses to integers.
    ZAP returns error strings like 'does_not_exist' instead of numbers on errors.
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _resolve_zap_path():
    """Return the absolute path to the OWASP ZAP executable if available."""
    explicit_path = os.environ.get('ZAP_PATH')
    if explicit_path and os.path.exists(explicit_path):
        return explicit_path

    zap_binary = which('zaproxy') or which('zap.sh')
    if zap_binary:
        return zap_binary

    # Check common macOS installation paths
    macos_paths = [
        '/Applications/ZAP.app/Contents/Java/zap.sh',
        '/Applications/OWASP ZAP.app/Contents/Java/zap.sh',
    ]
    for path in macos_paths:
        if os.path.exists(path):
            return path

    return None


def start_zap():
    """
    Spawns a new process running ZAP in daemon mode.
    """
    path = _resolve_zap_path()
    if not path:
        print('OWASP ZAP executable not found. Skipping proxy setup.')
        return False

    print(f'Starting OWASP ZAP from: {path}')
    subprocess.Popen(
        [path, '-daemon', '-config', 'api.disablekey=true', '-port', '8080'],
        stdout=open(os.devnull, 'w'),
        stderr=subprocess.STDOUT,
    )

    # Wait for ZAP to start up and be ready
    print('Waiting for ZAP to start...')
    sleep(15)
    print('ZAP should be ready')
    return True


@fixture
def start_firefox(context, zap_proxy=None):
    """
    Starts Firefox in headless mode, and proxying through ZAP.
    """
    from selenium.webdriver.common.proxy import Proxy, ProxyType
    
    options = Options()
    options.headless = True
    
    if zap_proxy:
        # Set up proxy for ZAP using Selenium 4 compatible method
        proxy = Proxy()
        proxy.proxy_type = ProxyType.MANUAL
        proxy.http_proxy = zap_proxy
        proxy.ssl_proxy = zap_proxy
        proxy.ftp_proxy = zap_proxy
        # The noProxy list contains domains which Firefox appears to make requests
        # to automatically. If those requests pass through ZAP when scans are
        # running, they interfere with the scans, so set them as not being proxied.
        proxy.no_proxy = ['digicert.com', 'firefox.com', 'mozilla.com', 'mozilla.net']
        
        options.proxy = proxy
    
    firefox_kwargs = {
        'options': options,
        'service': FirefoxService(executable_path=which('geckodriver') or 'geckodriver'),
    }

    context.browser = webdriver.Firefox(**firefox_kwargs)
    yield context.browser

    # Clean up once the tests finish.
    context.browser.quit()


def recreate_database():
    """
    Destroys and the recreates the SQLite database so each test run starts with
    a clean slate.
    """
    os.environ['DJANGO_SETTINGS_MODULE'] = 'djangogoat.settings'
    os.environ.setdefault('DJANGO_SECRET_KEY', 'insecure-behave-secret-key')
    django.setup()
    database_path = os.path.join(BASE_DIR, 'db.sqlite3')
    if os.path.exists(database_path):
        os.remove(database_path)
    call_command('migrate', '--noinput')


def before_all(context):
    """
    This function is run before the BDD tests are run.
    """
    recreate_database()
    context.base_url = DEFAULT_BASE_URL.rstrip('/')
    context.zap_enabled = start_zap()
    zap_proxy = 'localhost:8080' if context.zap_enabled else None
    use_fixture(start_firefox, context, zap_proxy=zap_proxy)


def after_all(context):
    """
    This function is run after the BDD tests are run. We use it to kick off the
    ZAP scanning.
    """
    if not getattr(context, 'zap_enabled', False):
        print('OWASP ZAP was not started; skipping active scanning.')
        return

    try:
        # General preparation.
        zap = ZAPv2(apikey=None)
        base_url = getattr(context, 'base_url', DEFAULT_BASE_URL).rstrip('/')
        logout_url_regex = '%s/logout.*' % base_url
        static_url_regex = '%s/static.*' % base_url
        # Set up the spider (simple, unauthenticated scanning).
        spider = zap.spider
        try:
            spider.exclude_from_scan(logout_url_regex)
            spider.exclude_from_scan(static_url_regex)
        except:
            pass  # Ignore errors in exclusions

        # Spider the app as an unauthenticated user.
        print('Spidering %s as an unauthenticated user.' % base_url)
        scan_id = spider.scan(base_url)
        status = _safe_int(spider.status(scan_id), 0)
        while status >= 0 and status < 100:
            print('Spider progress: %s%%' % status)
            sleep(5)
            status = _safe_int(spider.status(scan_id), 100)
        print('***RESULTS***')
        for result in sorted(spider.results()):
            print(result)
        print('')

        # # Give the passive scanner a chance to finish
        records = _safe_int(zap.pscan.records_to_scan, 0)
        while records > 0:
            sleep(1)
            records = _safe_int(zap.pscan.records_to_scan, 0)

        # Set up the active scanner for unauthenticated scanning.
        ascan = zap.ascan
        try:
            ascan.exclude_from_scan(logout_url_regex)
            ascan.exclude_from_scan(static_url_regex)
        except:
            pass  # Ignore errors in exclusions

        # Run basic active scan (unauthenticated)
        print('Starting active scan of %s' % base_url)
        scan_id = ascan.scan(base_url)
        status = _safe_int(ascan.status(scan_id), 0)
        while status >= 0 and status < 100:
            print('Active scan progress: %s%%' % status)
            sleep(5)
            status = _safe_int(ascan.status(scan_id), 100)

        print('All scans completed')

        # Report the results
        print('Zap hosts: ' + ', '.join(zap.core.hosts))
        alerts = zap.core.alerts()
        if alerts:
            print('There are %s Zap alerts.' % len(alerts))
            with open('report.html', 'w') as f:
                f.write(zap.core.htmlreport())
            print('A report has been saved.')
        else:
            print('There are no Zap alerts.')
    except Exception as e:
        print('Error during ZAP scanning: %s' % str(e))
        print('ZAP scanning incomplete, but continuing...')

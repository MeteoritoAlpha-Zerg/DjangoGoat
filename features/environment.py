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
from selenium.webdriver.common.proxy import Proxy, ProxyType

from zapv2 import ZAPv2


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BASE_URL = os.environ.get('DJANGO_GOAT_BASE_URL', 'http://localhost:8000')


def _resolve_zap_path():
    """Return the absolute path to the OWASP ZAP executable if available."""
    explicit_path = os.environ.get('ZAP_PATH')
    if explicit_path and os.path.exists(explicit_path):
        print(f'Using ZAP from ZAP_PATH: {explicit_path}')
        return explicit_path

    # Try standard command-line tools first
    zap_binary = which('zaproxy') or which('zap.sh')
    if zap_binary:
        print(f'Found ZAP in PATH: {zap_binary}')
        return zap_binary

    # Check common macOS installation paths
    macos_paths = [
        '/Applications/OWASP ZAP.app/Contents/Java/zap.sh',
        '/Applications/ZAP.app/Contents/Java/zap.sh',
        '/Applications/OWASP_ZAP.app/Contents/Java/zap.sh',
        '/opt/homebrew/bin/zap.sh',  # Homebrew on Apple Silicon
        '/usr/local/bin/zap.sh',      # Homebrew on Intel
        '/opt/homebrew/opt/zap/bin/zap.sh',
        '/usr/local/opt/zap/bin/zap.sh',
    ]
    
    for path in macos_paths:
        if os.path.exists(path):
            print(f'Found ZAP at: {path}')
            return path

    return None


def start_zap():
    """
    Spawns a new process running ZAP in daemon mode.
    """
    path = _resolve_zap_path()
    if not path:
        print('\n' + '='*60)
        print('WARNING: OWASP ZAP executable not found.')
        print('ZAP will not be used for security scanning.')
        print('='*60 + '\n')
        return False

    print('\n' + '='*60)
    print('OWASP ZAP: Starting daemon...')
    print(f'Using ZAP executable: {path}')
    print('='*60)
    
    # Start ZAP in daemon mode with API key disabled
    # The -daemon flag ensures ZAP runs headless without a GUI
    zap_process = subprocess.Popen(
        [path, '-daemon', '-config', 'api.disablekey=true', '-port', '8080'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    
    # Wait for ZAP to be ready by checking if the API is accessible
    print('Waiting for ZAP to start (this may take 20-30 seconds)...')
    zap = ZAPv2(apikey=None, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
    
    max_wait_time = 60  # Maximum wait time in seconds
    wait_interval = 2   # Check every 2 seconds
    elapsed = 0
    
    while elapsed < max_wait_time:
        try:
            # Try to connect to ZAP API
            version = zap.core.version
            print(f'✓ ZAP daemon started successfully (version: {version})')
            print('='*60 + '\n')
            return True
        except Exception:
            # ZAP not ready yet
            sleep(wait_interval)
            elapsed += wait_interval
            if elapsed % 10 == 0:
                print(f'  Still waiting... ({elapsed}s elapsed)')
    
    # If we get here, ZAP didn't start in time
    print('✗ ERROR: ZAP failed to start within timeout period')
    print('='*60 + '\n')
    zap_process.terminate()
    return False


@fixture
def start_firefox(context, zap_proxy=None):
    """
    Starts Firefox in headless mode, and proxying through ZAP.
    """
    options = Options()
    options.headless = True

    if zap_proxy:
        # The noProxy list contains domains which Firefox appears to make requests
        # to automatically. If those requests pass through ZAP when scans are
        # running, they interfere with the scans, so set them as not being proxied.
        proxy = Proxy({
            'proxyType': ProxyType.MANUAL,
            'ftpProxy': zap_proxy,
            'httpProxy': zap_proxy,
            'sslProxy': zap_proxy,
            'noProxy': [
                'digicert.com',
                'firefox.com',
                'mozilla.com',
                'mozilla.net',
            ],
        })
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
    print('\n' + '='*60)
    print('DATABASE: Clearing and recreating database...')
    print('='*60)
    
    os.environ['DJANGO_SETTINGS_MODULE'] = 'djangogoat.settings'
    os.environ.setdefault('DJANGO_SECRET_KEY', 'insecure-behave-secret-key')
    django.setup()
    database_path = os.path.join(BASE_DIR, 'db.sqlite3')
    
    if os.path.exists(database_path):
        os.remove(database_path)
        print('✓ Deleted existing database')
    else:
        print('✓ No existing database found')
    
    print('✓ Running migrations...')
    call_command('migrate', '--noinput')
    print('✓ Database ready - starting with clean slate')
    print('='*60 + '\n')


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

    # General preparation.
    zap = ZAPv2(apikey=None)
    base_url = getattr(context, 'base_url', DEFAULT_BASE_URL).rstrip('/')
    logged_out_indicator_regex = r'\QSign Up\E'
    logout_url_regex = '%s/logout.*' % base_url
    main_context_regex = '%s.*' % base_url
    static_url_regex = '%s/static.*' % base_url
    zap_context_name = 'Default Context'

    # Create or get ZAP's context. This means the range of URLs which ZAP will scan.
    # Note that Behave's context, as passed into this function, it a totally
    # different concept to ZAP's context.
    zap_context_id = zap.context.new_context(contextname=zap_context_name)
    print(f'Created ZAP context: {zap_context_name} (ID: {zap_context_id})')
    
    print(
        main_context_regex + ' -> ' +
        zap.context.include_in_context(
            contextname=zap_context_name,
            regex=main_context_regex
        )
    )

    # General script preparation.
    script = zap.script
    features_dir = os.path.join(BASE_DIR, 'features')
    script_engine = 'Oracle Nashorn'

    # Set up a custom ZAP Http Sender script which improves ZAP's handling of
    # Django CSRF tokens.
    http_sender_script_name = 'CSRFInterceptor.js'
    http_sender_script_path = os.path.join(
        features_dir,
        http_sender_script_name
    )
    print(
        'Load HTTP Sender script: ' + http_sender_script_name + ' -> ' +
        script.load(
            scriptname=http_sender_script_name,
            scripttype='httpsender',
            scriptengine=script_engine,
            filename=http_sender_script_path,
        )
    )
    print(
        'Enable HTTP Sender script: ' + http_sender_script_name + ' -> ' +
        script.enable(scriptname=http_sender_script_name)
    )

    # Set up Django-specific ZAP Authentication script.
    auth_method = 'scriptBasedAuthentication'
    auth_script_name = 'DjangoAuthentication.js'
    auth_script_path = os.path.join(features_dir, auth_script_name)
    print(
        'Load Authentication script: ' + auth_script_name + ' -> ' +
        script.load(
            scriptname=auth_script_name,
            scripttype='authentication',
            scriptengine=script_engine,
            filename=auth_script_path,
        )
    )

    # Set the authentication method.
    auth = zap.authentication
    authParams = (
        'scriptName=' + auth_script_name + '&'
        'Username field=username&'
        'Password field=password&'
        'Target URL=%s/login/' % base_url,
    )
    print(
        'Set authentication method: ' + auth_method + ' -> ' +
        auth.set_authentication_method(
            contextid=zap_context_id,
            authmethodname=auth_method,
            authmethodconfigparams=authParams
        )
    )

    # Set the logged-out indicator.
    print(
        'Define LoggedOut indicator: ' + logged_out_indicator_regex +
        ' -> ' +
        auth.set_logged_out_indicator(
            contextid=zap_context_id,
            loggedoutindicatorregex=logged_out_indicator_regex
        )
    )

    # Define the users
    # Note that the ZAP scans are run once for each user, so defining 3 users
    # means ZAP will scan your app three times. Only define more than one user
    # here if you have different types of users which you'd like ZAP to scan
    # for.
    users = zap.users
    user_list = [
        {
            'name': 'ImBaaaaad',
            'credentials': 'Username=ImBaaaaad&Password=Appletr33!'
        }
    ]
    user_ids = []
    for user in user_list:
        username = user.get('name')
        print('Creating user ' + username)
        user_id = users.new_user(contextid=zap_context_id, name=username)
        user_ids.append(user_id)
        print(
            'User ID: ' + user_id + '; username -> ' +
            users.set_user_name(
                contextid=zap_context_id, userid=user_id, name=username
            ) +
            '; credentials -> ' +
            users.set_authentication_credentials(
                contextid=zap_context_id,
                userid=user_id,
                authcredentialsconfigparams=user.get('credentials')
            ) +
            '; enabled -> ' +
            users.set_user_enabled(
                contextid=zap_context_id, userid=user_id, enabled=True
            )
        )

    # Set up the spider.
    # The logout url is excluded so that ZAP can't log itself out by mistake.
    # The static files are excluded because they slow the scan down for no real
    # benefit.
    spider = zap.spider
    spider.exclude_from_scan(logout_url_regex)
    spider.exclude_from_scan(static_url_regex)

    # Spider the app as an unauthenticated user.
    print('Spidering %s as an unauthenticated user.' % base_url)
    scan_id = spider.scan(base_url)
    print(f'Spider scan started with ID: {scan_id}')
    
    # Wait for spider to complete with timeout
    max_spider_time = 300  # 5 minutes max
    elapsed = 0
    while elapsed < max_spider_time:
        try:
            status = int(spider.status(scan_id))
            if status >= 100:
                break
            print('Spider progress: %s%%' % status)
            sleep(5)
            elapsed += 5
        except (ValueError, Exception) as e:
            print(f'Spider status check failed: {e}')
            break
    
    if elapsed >= max_spider_time:
        print('Spider scan timed out after %s seconds' % max_spider_time)
    
    print('***RESULTS***')
    try:
        for result in sorted(spider.results(scan_id)):
            print(result)
    except Exception as e:
        print(f'Error getting spider results: {e}')
    print('')

    # Give the passive scanner a chance to finish
    print('Waiting for passive scanner...')
    pscan_timeout = 60
    elapsed = 0
    while elapsed < pscan_timeout:
        try:
            records = int(zap.pscan.records_to_scan)
            if records <= 0:
                break
            sleep(1)
            elapsed += 1
        except Exception:
            break
    print('Passive scanner done')

    # Set up the active scanner.
    # The logout url is excluded so that ZAP can't log itself out by mistake.
    # The static files are excluded because they slow the scan down for no real
    # benefit.
    ascan = zap.ascan
    ascan.exclude_from_scan(logout_url_regex)
    ascan.exclude_from_scan(static_url_regex)

    # Scan the app one user at a time.
    for user_id in user_ids:
        print('Starting scans as user %s.' % user_id)

        # Run the spider.
        try:
            scan_id = spider.scan_as_user(
                contextid=zap_context_id,
                userid=user_id,
                url=base_url,
                maxchildren=None,
                recurse=True,
                subtreeonly=None
            )
            print('Spidering (scan id %s).' % scan_id)
            sleep(5)
            
            # Wait for spider with timeout
            max_time = 300
            elapsed = 0
            while elapsed < max_time:
                try:
                    status = int(spider.status(scan_id))
                    if status >= 100:
                        break
                    print('Progress: %s%%' % status)
                    sleep(2)
                    elapsed += 2
                except (ValueError, Exception) as e:
                    print(f'Spider status error: {e}')
                    break
            
            print('***RESULTS***')
            try:
                for result in sorted(zap.spider.results(scan_id)):
                    print(result)
            except Exception as e:
                print(f'Error getting results: {e}')
            print('')
        except Exception as e:
            print(f'Spider scan failed for user {user_id}: {e}')

        # Give the passive scanner a chance to finish
        print('Waiting for passive scanner...')
        elapsed = 0
        while elapsed < 60:
            try:
                records = int(zap.pscan.records_to_scan)
                if records <= 0:
                    break
                sleep(1)
                elapsed += 1
            except Exception:
                break

        # Run the active scan.
        try:
            scan_id = ascan.scan_as_user(
                url=base_url,
                contextid=zap_context_id,
                userid=user_id,
                recurse=True,
                scanpolicyname=None,
                method=None,
                postdata=True
            )
            print('Active scanning (scan id %s).' % scan_id)
            
            # Wait for active scan with timeout
            max_time = 600  # 10 minutes for active scan
            elapsed = 0
            while elapsed < max_time:
                try:
                    status = int(ascan.status(scan_id))
                    if status >= 100:
                        break
                    print('Progress: %s%%' % status)
                    sleep(5)
                    elapsed += 5
                except (ValueError, Exception) as e:
                    print(f'Active scan status error: {e}')
                    break
        except Exception as e:
            print(f'Active scan failed for user {user_id}: {e}')

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

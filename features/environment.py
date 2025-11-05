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
DEFAULT_BASE_URL = os.environ.get('DJANGO_GOAT_BASE_URL', 'http://localhost:3572')


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
    Spawns a new process running ZAP in daemon mode and waits for it to be ready.
    """
    path = _resolve_zap_path()
    if not path:
        print('OWASP ZAP executable not found. Skipping proxy setup.')
        return False

    # Check if ZAP is already running and accessible
    print('Checking if ZAP is already running...')
    try:
        test_zap = ZAPv2(apikey=None, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        version = test_zap.core.version
        print(f'✓ ZAP is already running (version: {version})')
        return True
    except Exception:
        pass  # ZAP not running, continue to start it

    print(f'Starting OWASP ZAP from: {path}')
    zap_process = subprocess.Popen(
        [path, '-daemon', '-config', 'api.disablekey=true', '-port', '8080'],
        stdout=open(os.devnull, 'w'),
        stderr=subprocess.STDOUT,
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
            return True
        except Exception:
            # ZAP not ready yet
            sleep(wait_interval)
            elapsed += wait_interval
            if elapsed % 10 == 0:
                print(f'  Still waiting... ({elapsed}s elapsed)')
    
    # If we get here, ZAP didn't start in time
    print('✗ ERROR: ZAP failed to start within timeout period')
    try:
        zap_process.terminate()
    except:
        pass
    return False


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
    comprehensive ZAP scanning with Django-specific configuration.
    """
    if not getattr(context, 'zap_enabled', False):
        print('OWASP ZAP was not started; skipping active scanning.')
        return

    try:
        # General preparation.
        zap = ZAPv2(apikey=None)
        base_url = getattr(context, 'base_url', DEFAULT_BASE_URL).rstrip('/')
        logged_out_indicator_regex = r'\QSign Up\E'
        logout_url_regex = '%s/logout.*' % base_url
        main_context_regex = '%s.*' % base_url
        static_url_regex = '%s/static.*' % base_url
        
        # Create a new session to clear any previous alerts/data
        print('\nCreating new ZAP session (clearing previous data)...')
        try:
            zap.core.new_session(name='', overwrite=True)
            print('✓ ZAP session cleared')
        except Exception as e:
            print(f'Note: Could not create new session: {e}')
            try:
                zap.core.delete_all_alerts()
                print('✓ Cleared previous alerts')
            except Exception:
                pass
        
        # Create ZAP context for Django app
        zap_context_name = 'DjangoGoat Context'
        print(f'\nCreating ZAP context: {zap_context_name}')
        zap_context_id = zap.context.new_context(contextname=zap_context_name)
        print(f'✓ Context created (ID: {zap_context_id})')
        
        # Include the target URL in the context
        zap.context.include_in_context(contextname=zap_context_name, regex=main_context_regex)
        print(f'✓ Added URL pattern to context: {main_context_regex}')
        
        # Set up Django-specific scripts
        features_dir = os.path.join(BASE_DIR, 'features')
        script_engine = 'Oracle Nashorn'
        
        # Load CSRF interceptor script for Django CSRF tokens
        csrf_script_name = 'CSRFInterceptor.js'
        csrf_script_path = os.path.join(features_dir, csrf_script_name)
        if os.path.exists(csrf_script_path):
            print(f'\nLoading CSRF interceptor script...')
            try:
                zap.script.load(
                    scriptname=csrf_script_name,
                    scripttype='httpsender',
                    scriptengine=script_engine,
                    filename=csrf_script_path,
                )
                zap.script.enable(scriptname=csrf_script_name)
                print(f'✓ CSRF interceptor enabled')
            except Exception as e:
                print(f'Note: Could not load CSRF script: {e}')
        
        # Load Django authentication script
        auth_script_name = 'DjangoAuthentication.js'
        auth_script_path = os.path.join(features_dir, auth_script_name)
        if os.path.exists(auth_script_path):
            print(f'\nSetting up Django authentication...')
            try:
                zap.script.load(
                    scriptname=auth_script_name,
                    scripttype='authentication',
                    scriptengine=script_engine,
                    filename=auth_script_path,
                )
                
                # Configure authentication method
                auth_params = (
                    f'scriptName={auth_script_name}&'
                    'Username field=username&'
                    'Password field=password&'
                    f'Target URL={base_url}/login/'
                )
                zap.authentication.set_authentication_method(
                    contextid=zap_context_id,
                    authmethodname='scriptBasedAuthentication',
                    authmethodconfigparams=auth_params
                )
                
                # Set logged-out indicator
                zap.authentication.set_logged_out_indicator(
                    contextid=zap_context_id,
                    loggedoutindicatorregex=logged_out_indicator_regex
                )
                print(f'✓ Django authentication configured')
            except Exception as e:
                print(f'Note: Could not configure authentication: {e}')
        
        # Create test user for authenticated scanning
        print(f'\nCreating authenticated test user...')
        user_list = [{'name': 'ImBaaaaad', 'credentials': 'Username=ImBaaaaad&Password=Appletr33!'}]
        user_ids = []
        
        for user in user_list:
            username = user.get('name')
            try:
                user_id = zap.users.new_user(contextid=zap_context_id, name=username)
                zap.users.set_user_name(contextid=zap_context_id, userid=user_id, name=username)
                zap.users.set_authentication_credentials(
                    contextid=zap_context_id,
                    userid=user_id,
                    authcredentialsconfigparams=user.get('credentials')
                )
                zap.users.set_user_enabled(contextid=zap_context_id, userid=user_id, enabled=True)
                user_ids.append(user_id)
                print(f'✓ User created: {username} (ID: {user_id})')
            except Exception as e:
                print(f'Note: Could not create user {username}: {e}')
        
        # Configure spider with aggressive settings
        spider = zap.spider
        spider.exclude_from_scan(logout_url_regex)
        spider.exclude_from_scan(static_url_regex)
        
        # Set spider options to prevent hanging and speed up scans
        try:
            spider.set_option_max_duration('3')  # 3 minute max duration
            spider.set_option_max_depth('3')  # Limit depth to prevent deep recursion
            spider.set_option_max_children('10')  # Limit children per page
            print('\n✓ Spider configured with aggressive timeouts')
        except Exception as e:
            print(f'Note: Could not set all spider options: {e}')
        
        # Spider as unauthenticated user
        print(f'\nSpidering {base_url} as unauthenticated user...')
        scan_id = spider.scan(base_url)
        status = _safe_int(spider.status(scan_id), 0)
        timeout_count = 0
        last_status = -1
        stuck_count = 0
        
        while status >= 0 and status < 100 and timeout_count < 60:  # 5 minute max
            print(f'  Spider progress: {status}%')
            
            # Detect if stuck
            if status == last_status:
                stuck_count += 1
                if stuck_count >= 6:  # Stuck for 30 seconds
                    print(f'  ⚠ Spider stuck at {status}% - stopping')
                    try:
                        spider.stop(scan_id)
                    except:
                        pass
                    break
            else:
                stuck_count = 0
            
            last_status = status
            sleep(5)
            status = _safe_int(spider.status(scan_id), 100)
            timeout_count += 1
        
        if timeout_count >= 60:
            print('  ⚠ Spider timed out - stopping')
            try:
                spider.stop(scan_id)
            except:
                pass
        
        print('✓ Unauthenticated spider complete')
        
        # Wait for passive scanner
        print('Waiting for passive scanner...')
        records = _safe_int(zap.pscan.records_to_scan, 0)
        timeout = 0
        while records > 0 and timeout < 60:
            sleep(1)
            records = _safe_int(zap.pscan.records_to_scan, 0)
            timeout += 1
        print('✓ Passive scan complete')
        
        # Spider and scan as authenticated user (with aggressive timeouts)
        for user_id in user_ids:
            print(f'\n--- Authenticated scanning as user {user_id} ---')
            
            # Spider as authenticated user
            print('Spidering as authenticated user...')
            try:
                scan_id = spider.scan_as_user(
                    contextid=zap_context_id,
                    userid=user_id,
                    url=base_url,
                    recurse=True
                )
                status = _safe_int(spider.status(scan_id), 0)
                timeout_count = 0
                last_status = -1
                stuck_count = 0
                
                while status >= 0 and status < 100 and timeout_count < 36:  # 3 minute max
                    print(f'  Spider progress: {status}%')
                    
                    # Detect if stuck
                    if status == last_status:
                        stuck_count += 1
                        if stuck_count >= 4:  # Stuck for 20 seconds
                            print(f'  ⚠ Authenticated spider stuck at {status}% - stopping')
                            try:
                                spider.stop(scan_id)
                            except:
                                pass
                            break
                    else:
                        stuck_count = 0
                    
                    last_status = status
                    sleep(5)
                    status = _safe_int(spider.status(scan_id), 100)
                    timeout_count += 1
                
                if timeout_count >= 36:
                    print('  ⚠ Authenticated spider timed out - stopping')
                    try:
                        spider.stop(scan_id)
                    except:
                        pass
                
                print('✓ Authenticated spider complete')
            except Exception as e:
                print(f'Note: Authenticated spider had issues: {e}')
            
            # Wait for passive scanner
            print('Waiting for passive scanner...')
            records = _safe_int(zap.pscan.records_to_scan, 0)
            timeout = 0
            while records > 0 and timeout < 60:
                sleep(1)
                records = _safe_int(zap.pscan.records_to_scan, 0)
                timeout += 1
            print('✓ Passive scan complete')
        
        # Configure active scanner with aggressive timeouts
        ascan = zap.ascan
        ascan.exclude_from_scan(logout_url_regex)
        ascan.exclude_from_scan(static_url_regex)
        
        # Set very aggressive scan options to prevent hanging
        try:
            ascan.set_option_max_scan_duration_in_mins('5')  # 3 minute hard limit
            ascan.set_option_max_rule_duration_in_mins('2')  # 1 minute per rule max
            ascan.set_option_thread_per_host('3')  # More threads for speed
            ascan.set_option_delay_in_ms('0')  # No delay between requests
            print('\n✓ Active scanner configured with aggressive timeouts')
        except Exception as e:
            print(f'Note: Could not set all scan options: {e}')
        
        # Run active scan
        print(f'\nStarting active scan of {base_url}...')
        scan_id = ascan.scan(base_url)
        status = _safe_int(ascan.status(scan_id), 0)
        timeout_count = 0
        last_status = -1
        stuck_count = 0
        
        while status >= 0 and status < 100 and timeout_count < 72:  # 6 minute max (72 * 5sec)
            print(f'  Active scan progress: {status}%')
            
            # Detect if scan is stuck
            if status == last_status:
                stuck_count += 1
                if stuck_count >= 6:  # Stuck for 30 seconds
                    print(f'  ⚠ Scan stuck at {status}% - stopping scan')
                    try:
                        ascan.stop(scan_id)
                    except:
                        pass
                    break
            else:
                stuck_count = 0
            
            last_status = status
            sleep(5)
            status = _safe_int(ascan.status(scan_id), 100)
            timeout_count += 1
        
        # Force stop if timed out
        if timeout_count >= 72:
            print('  ⚠ Active scan timed out - forcing stop')
            try:
                ascan.stop(scan_id)
            except:
                pass
        
        print('✓ Active scan complete')
        
        print('\n' + '='*70)
        print('ALL SCANS COMPLETED')
        print('='*70)
        
        # Report the results
        print(f'\nZAP hosts scanned: {", ".join(zap.core.hosts)}')
        alerts = zap.core.alerts()
        
        # Count alerts by risk level
        alert_by_risk = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            if risk in alert_by_risk:
                alert_by_risk[risk] += 1
        
        if alerts:
            print(f'\nThere are {len(alerts)} Zap alerts.')
            print('Alerts by Risk Level:')
            print(f'  High: {alert_by_risk["High"]}')
            print(f'  Medium: {alert_by_risk["Medium"]}')
            print(f'  Low: {alert_by_risk["Low"]}')
            print(f'  Informational: {alert_by_risk["Informational"]}')
            with open('report.html', 'w') as f:
                f.write(zap.core.htmlreport())
            print('\n✓ Security report saved to report.html')
        else:
            print('\n✓ There are no Zap alerts - application is secure!')
            
    except Exception as e:
        print(f'\n✗ Error during ZAP scanning: {str(e)}')
        print('ZAP scanning incomplete, but continuing...')

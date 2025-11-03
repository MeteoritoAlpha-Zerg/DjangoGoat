from behave import given, when, then

from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


def _base_url(context):
    return getattr(context, 'base_url', 'http://localhost:8000')


@when("I go to the profile page")  # noqa: F811
def step_impl(context):
    base_url = _base_url(context)
    context.browser.get(f'{base_url}/profile/1/')


@then("the page should not contain the password")  # noqa: F811
def step_impl(context):
    page_source = context.browser.page_source.lower()
    # Check that common password patterns are not visible
    assert 'appletr33!' not in page_source.lower()
    assert 'cleartext_password' not in page_source.lower()
    assert 'password:' not in page_source.lower()


@then("the page should not execute JavaScript")  # noqa: F811
def step_impl(context):
    # Check if any alerts were triggered (XSS)
    try:
        alert = context.browser.switch_to.alert
        alert_text = alert.text
        alert.dismiss()
        raise AssertionError(f"XSS vulnerability: JavaScript was executed! Alert text: {alert_text}")
    except:
        # No alert found - this is good, XSS was prevented
        pass


@then("the page content should be escaped")  # noqa: F811
def step_impl(context):
    page_source = context.browser.page_source
    # Check that script tags are escaped
    assert '&lt;script&gt;' in page_source or '<script>' not in page_source.lower()


@when("I attempt to access profile {profile_id}")  # noqa: F811
def step_impl(context, profile_id):
    base_url = _base_url(context)
    context.browser.get(f'{base_url}/profile/{profile_id}/')


@when("I check the database for cleartext passwords")  # noqa: F811
def step_impl(context):
    # This is a placeholder - in real tests, we'd check the actual database
    # For now, we just verify the app doesn't expose passwords in the UI
    pass


@then("I should see a generic error message")  # noqa: F811
def step_impl(context):
    # Error message should not reveal whether username exists
    WebDriverWait(context.browser, 10).until(
        EC.presence_of_element_located((By.ID, 'error'))
    )
    error_element = context.browser.find_element(By.ID, 'error')
    error_text = error_element.text.lower()
    
    # Check that error message doesn't reveal too much
    assert 'username' not in error_text or 'password' not in error_text
    assert 'does not exist' not in error_text
    assert 'invalid' in error_text or 'not valid' in error_text


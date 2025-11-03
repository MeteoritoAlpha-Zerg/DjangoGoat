Feature: Security Vulnerabilities
  # These tests check for security vulnerabilities that should be fixed
  # On the "broken" branch, many of these tests WILL FAIL (exposing vulnerabilities)
  # On the "fixed" branch, these tests should PASS (vulnerabilities fixed)
  # 
  # Note: These tests use existing users created in authentication.feature

  @security @sql_injection
  Scenario: SQL Injection should not bypass authentication
    # The broken version has SQL injection in login (views.py line 46-55)
    # It uses raw SQL with string formatting: WHERE username = '%s' AND password = '%s'
    Given I'm on the login page
    When I enter invalid credentials "admin' OR '1'='1" and "anything" and push the login button
    Then I see an error message
    And I'm not logged in

  @security @sql_injection
  Scenario: SQL Injection with comment should not bypass authentication
    Given I'm on the login page
    When I enter invalid credentials "admin'--" and "anything" and push the login button
    Then I see an error message
    And I'm not logged in

  @security @idor
  Scenario: IDOR - Cannot access other users' private notes
    # The broken version doesn't check authorization in note view (views.py line 59-61)
    # Users can view any note by manipulating the ID parameter
    Given I'm on the login page
    When I enter valid credentials "ImBaaaaad" and "Appletr33!" and push the login button
    Then I'm logged in
    When I force browse to note 1
    Then I see the 404 page

  @security @xss
  Scenario: XSS protection in user bio
    Given I'm on the login page
    When I enter valid credentials "TestyMcFirstson" and "Appletr33!" and push the login button
    Then I'm logged in
    When I click the edit profile button
    Then I see the profile update page
    When I add a new "<script>alert('XSS')</script>" and click the update button
    Then I see the profile page
    And the page should not execute JavaScript

  @security @xss
  Scenario: XSS protection in note content
    Given I'm on the login page
    When I enter valid credentials "TestrikDeuce" and "Appletr33!" and push the login button
    Then I'm logged in
    And I see the dashboard
    When I click 'start a conversation'
    Then I see the write note form
    When I write a note to "TestyMcFirstson" with "<img src=x onerror=alert('XSS')>"
    Then I see the dashboard
    And the page should not execute JavaScript

  @security @cleartext_password
  Scenario: Passwords should not be stored in cleartext
    # The broken version stores cleartext passwords in UserProfile model (models.py line 15)
    # and uses them for authentication (views.py line 52)
    Given I'm on the login page
    When I enter valid credentials "ThriceVonTesterbergIII" and "Appletr33!" and push the login button
    Then I'm logged in
    When I go to the profile page
    Then the page should not contain the password

  @security @weak_password
  Scenario Outline: Weak passwords should be rejected
    # The broken version has AUTH_PASSWORD_VALIDATORS = [] (settings.py line 98)
    # This allows weak passwords
    Given I'm on the sign up page
    When I create "<username>" user with "<weak_password>" password
    Then I'm not logged in

    Examples: Weak Passwords
      | username       | weak_password |
      | WeakPwd1       | 123456        |
      | WeakPwd2       | password      |
      | WeakPwd3       | 12345678      |
      | WeakPwd4       | abc123        |

  @security @session_security
  Scenario: Insecure session cookies
    # The broken version has SESSION_COOKIE_HTTPONLY = False (settings.py line 140)
    # This makes cookies accessible to JavaScript, enabling XSS cookie theft
    Given I'm on the login page
    When I enter valid credentials "NaughtyGoat" and "Appletr33!" and push the login button
    Then I'm logged in
    # In a proper test, we'd check cookie flags via browser API

  @security @information_disclosure
  Scenario: Debug mode should be disabled in production
    # The broken version has DEBUG = True (settings.py line 27)
    # This exposes sensitive information in error pages
    Given I'm on the landing page
    # In a proper test, we'd trigger an error and check if debug info is exposed

  @security @auth
  Scenario: Unauthenticated access to protected resources
    Given I'm on the landing page
    And I'm not logged in
    When I force browse to note 1
    Then I see the login page
    # Unauthenticated users should be redirected to login

  @security @enumeration
  Scenario: Login errors should not reveal account existence
    # Error messages should be generic to prevent account enumeration
    Given I'm on the login page
    When I enter invalid credentials "NonExistentUser99999" and "wrongpassword" and push the login button
    Then I should see a generic error message
    And I'm not logged in


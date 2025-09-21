#!/usr/bin/env python
"""
Test runner for the OTP-based authentication system.
Run this script to test all authentication-related functionality.
"""

import os
import sys
import django
from django.test.utils import get_runner
from django.conf import settings

def run_auth_tests():
    """Run all authentication-related tests"""

    # Setup Django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    django.setup()

    TestRunner = get_runner(settings)
    test_runner = TestRunner()

    # Define test suites to run
    test_suites = [
        # OTP App Tests
        'apps.otp.tests.OTPModelTestCase',
        'apps.otp.tests.OTPUtilityTestCase',
        'apps.otp.tests.OTPSerializerTestCase',
        'apps.otp.tests.OTPViewTestCase',
        'apps.otp.tests.OTPSecurityTestCase',

        # Users App Tests (updated for OTP)
        'apps.users.tests.UserSignupTestCase.test_valid_signup',
        'apps.users.tests.UserLoginTestCase',
        'apps.users.tests.UserLogoutTestCase',
        'apps.users.tests.ForgotPasswordTestCase',
        'apps.users.tests.UpdatePasswordTestCase.test_update_password_step1_send_otp',
        'apps.users.tests.UpdatePasswordTestCase.test_update_password_step2_verify_otp_and_update',

        # Integration Tests
        'apps.users.test_otp_integration.OTPAuthenticationIntegrationTestCase',
    ]

    print("🔐 Running OTP-based Authentication System Tests")
    print("=" * 60)

    total_failures = 0

    for suite in test_suites:
        print(f"\n📋 Running {suite}...")
        failures = test_runner.run_tests([suite])
        total_failures += failures

        if failures == 0:
            print(f"✅ {suite} - PASSED")
        else:
            print(f"❌ {suite} - FAILED ({failures} failures)")

    print("\n" + "=" * 60)
    if total_failures == 0:
        print("🎉 ALL AUTHENTICATION TESTS PASSED!")
        print("✅ Your OTP-based authentication system is working correctly.")
    else:
        print(f"💥 SOME TESTS FAILED ({total_failures} total failures)")
        print("❌ Please review the failures above and fix the issues.")

    print("\n📊 Test Coverage Areas:")
    print("  - ✅ OTP Model (creation, expiration, validation)")
    print("  - ✅ OTP Utilities (generation, sending, hashing)")
    print("  - ✅ OTP Serializers (verification, request validation)")
    print("  - ✅ OTP Views (send, verify, resend)")
    print("  - ✅ OTP Security (single-use, purpose validation)")
    print("  - ✅ User Signup (with OTP verification)")
    print("  - ✅ User Login (direct, no OTP required)")
    print("  - ✅ User Logout (token blacklisting)")
    print("  - ✅ Password Reset (OTP-based)")
    print("  - ✅ Password Update (2-step with OTP)")
    print("  - ✅ Integration Workflows (complete flows)")
    print("  - ✅ Security Validations (permissions, rate limiting)")

    return total_failures


if __name__ == '__main__':
    failures = run_auth_tests()
    sys.exit(failures)
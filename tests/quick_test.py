"""Quick diagnostic test for rate limiting"""
import requests

BASE_URL = "http://127.0.0.1:8000"

print("Testing OTP Send endpoint...")
print("="*60)

response = requests.post(
    f"{BASE_URL}/api/v1/otp/send/",
    json={"email_or_phone": "abdullatifsadiq21@gmail.com", "purpose": "signup"},
    headers={"Content-Type": "application/json"}
)

print(f"Status Code: {response.status_code}")
print(f"Headers: {dict(response.headers)}")

if response.status_code == 500:
    print("\n❌ 500 Error - Check Django server logs for the error")
    print("\nResponse (first 500 chars):")
    print(response.text[:500])
else:
    print(f"\nResponse:")
    try:
        print(response.json())
    except:
        print(response.text[:500])

print("\n" + "="*60)
print("Check your Django terminal for error logs!")

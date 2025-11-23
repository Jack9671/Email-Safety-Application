"""
Simple test script to verify the API is working
"""
import requests
import json

API_URL = "http://localhost:8000"

def test_health():
    """Test health endpoint"""
    print("\n" + "="*60)
    print("Testing /health endpoint...")
    print("="*60)
    try:
        response = requests.get(f"{API_URL}/health", timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_spam_detection():
    """Test spam detection endpoint"""
    print("\n" + "="*60)
    print("Testing /scan/spam endpoint...")
    print("="*60)
    
    test_email = "Congratulations! You've won a FREE iPhone! Click here to claim your prize now!"
    
    try:
        response = requests.post(
            f"{API_URL}/scan/spam",
            json={"email_text": test_email},
            timeout=10
        )
        print(f"Status Code: {response.status_code}")
        result = response.json()
        print(f"Result: {json.dumps(result, indent=2)}")
        print(f"\n✅ Prediction: {'SPAM' if result['is_spam'] else 'HAM'}")
        print(f"   Confidence: {result['confidence']*100:.2f}%")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_model_info():
    """Test model info endpoint"""
    print("\n" + "="*60)
    print("Testing /model/info endpoint...")
    print("="*60)
    try:
        response = requests.get(f"{API_URL}/model/info", timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("\n" + "="*60)
    print("EMAIL SECURITY API - TEST SUITE")
    print("="*60)
    print(f"Testing API at: {API_URL}")
    
    results = []
    results.append(("Health Check", test_health()))
    results.append(("Model Info", test_model_info()))
    results.append(("Spam Detection", test_spam_detection()))
    
    print("\n" + "="*60)
    print("TEST RESULTS SUMMARY")
    print("="*60)
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name:<20} {status}")
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! API is working correctly.")
    else:
        print("\n⚠️ Some tests failed. Please check the API.")

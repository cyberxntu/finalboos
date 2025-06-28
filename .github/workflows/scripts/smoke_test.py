import requests
import sys

def smoke_test(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            print(f"[SUCCESS] Smoke test passed for {url}")
            sys.exit(0)  
        else:
            print(f"[FAIL] Smoke test failed for {url} with status code {response.status_code}")
            sys.exit(1) 
    except Exception as e:
        print(f"[ERROR] Smoke test error for {url}: {e}")
        sys.exit(1)  

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python smoke_test.py <URL>")
        sys.exit(1)
    smoke_test(sys.argv[1])

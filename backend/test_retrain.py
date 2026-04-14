import requests
import time

def test_retrain():
    print("Testing Retrain Endpoint...")
    # First login to get a token
    try:
        res = requests.post("http://localhost:5000/api/auth/login", json={
            "email": "admin@example.com", # Assumes exist
            "password": "password123", # Assumes exist
            "device_fingerprint": "test_device"
        })
        if res.status_code == 200:
            token = res.json().get('token')
            retrain_res = requests.post("http://localhost:5000/api/alerts/retrain", 
                headers={"Authorization": f"Bearer {token}"})
            print(f"Retrain response: {retrain_res.status_code} - {retrain_res.text}")
        else:
            print("Couldn't login to test retrain. Needs a valid user.")
    except Exception as e:
        print(f"Error testing retrain: {e}")

if __name__ == "__main__":
    test_retrain()

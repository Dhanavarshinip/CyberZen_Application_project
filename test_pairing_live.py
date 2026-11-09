import urllib.request
import json

def test():
    # 1. Unpaired test (no device_id)
    url_blank = 'https://cyberzen.13.211.114.156.sslip.io/api/extension/active-pairing'
    with urllib.request.urlopen(url_blank) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        print('1. Blank Active Pairing:', data)
        assert data['is_paired'] is False
        assert data['email'] is None

    # 2. Unregistered device test
    url_alice = 'https://cyberzen.13.211.114.156.sslip.io/api/extension/active-pairing?device_id=DEV_UNREGISTERED_DEVICE'
    with urllib.request.urlopen(url_alice) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        print('2. Unregistered Device:', data)
        assert data['is_paired'] is False
        assert data['email'] is None

    # 3. Pair new device to susmithadola9@gmail.com
    pair_url = 'https://cyberzen.13.211.114.156.sslip.io/api/extension/pair'
    pair_payload = {'email': 'susmithadola9@gmail.com', 'device_id': 'DEV_SUSMITHA_LAPTOP'}
    req = urllib.request.Request(pair_url, data=json.dumps(pair_payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as resp:
        pair_res = json.loads(resp.read().decode('utf-8'))
        print('3. Pair Response:', pair_res)
        assert pair_res.get('paired') is True or pair_res.get('status') == 'paired'
        assert pair_res['device_id'] == 'DEV_SUSMITHA_LAPTOP'

    # 4. Check active pairing for that specific device
    check_url = 'https://cyberzen.13.211.114.156.sslip.io/api/extension/active-pairing?device_id=DEV_SUSMITHA_LAPTOP'
    with urllib.request.urlopen(check_url) as resp:
        check_data = json.loads(resp.read().decode('utf-8'))
        print('4. Active Pairing for DEV_SUSMITHA_LAPTOP:', check_data)
        assert check_data['is_paired'] is True
        assert check_data['email'] == 'susmithadola9@gmail.com'

    # 5. Check another laptop DEV_OTHER_LAPTOP — must remain unpaired!
    other_url = 'https://cyberzen.13.211.114.156.sslip.io/api/extension/active-pairing?device_id=DEV_OTHER_LAPTOP'
    with urllib.request.urlopen(other_url) as resp:
        other_data = json.loads(resp.read().decode('utf-8'))
        print('5. Active Pairing for DEV_OTHER_LAPTOP:', other_data)
        assert other_data['is_paired'] is False
        assert other_data['email'] is None

    print('\n[SUCCESS] ALL MULTI-USER ISOLATION TESTS PASSED PERFECTLY!')

if __name__ == '__main__':
    test()

import urllib.request
import json

ev_url = 'https://cyberzen.13.211.114.156.sslip.io/api/browser/event'
ev_payload = {
    'url': 'https://en.wikipedia.org/wiki/Computer_security',
    'title': 'Computer security - Wikipedia',
    'device_id': 'DEV_SUSMITHA_LAPTOP',
    'user_id': 'usr_6b738fbb12'
}
req = urllib.request.Request(ev_url, data=json.dumps(ev_payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
with urllib.request.urlopen(req) as resp:
    res = json.loads(resp.read().decode('utf-8'))
    print('EVENT RECORDED:', res.get('status'), res.get('domain'))

get_url = 'https://cyberzen.13.211.114.156.sslip.io/api/telemetry/events?device_id=DEV_SUSMITHA_LAPTOP'
with urllib.request.urlopen(get_url) as resp:
    data = json.loads(resp.read().decode('utf-8'))
    print('EVENTS FOR DEV_SUSMITHA_LAPTOP count:', data.get('total'))
    if data.get('events'):
        print('LATEST EVENT:', data['events'][0].get('features', {}).get('display_name'), data['events'][0].get('device_id'))

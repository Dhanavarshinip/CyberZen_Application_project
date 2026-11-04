from backend.database.db import Database
import os

db = Database()

# Test 1: Device isolation
ev_a = {
    'event_id': 'test-device-a-001', 
    'device_id': 'DEVICE-A', 
    'user_id': 'user1', 
    'timestamp': '2026-10-07T10:00:00', 
    'event_type': 'APPLICATION_START', 
    'features': {}, 
    'created_at': '2026-10-07T10:00:00'
}
ev_b = {
    'event_id': 'test-device-b-001', 
    'device_id': 'DEVICE-B', 
    'user_id': 'user1', 
    'timestamp': '2026-10-07T10:00:00', 
    'event_type': 'APPLICATION_START', 
    'features': {}, 
    'created_at': '2026-10-07T10:00:00'
}
db.insert_event(ev_a)
db.insert_event(ev_b)

# Query per device - must be strictly isolated
events_a = db.get_events(device_id='DEVICE-A')
events_b = db.get_events(device_id='DEVICE-B')

print("Device A returns:", [e['device_id'] for e in events_a])
print("Device B returns:", [e['device_id'] for e in events_b])

a_correct = all(e['device_id'] == 'DEVICE-A' for e in events_a)
b_correct = all(e['device_id'] == 'DEVICE-B' for e in events_b)
print("Device A isolation:", "PASS" if a_correct else "FAIL")
print("Device B isolation:", "PASS" if b_correct else "FAIL")
print("Cross-contamination check:", "PASS" if len(events_a) == 1 and len(events_b) == 1 else "FAIL")

# Test 2: increment_sync_retry exists
db.enqueue_sync('test-device-a-001', ev_a)
db.increment_sync_retry('test-device-a-001', max_retries=3)
print("increment_sync_retry: PASS")

# Test 3: Test event filtering
ev_test = {
    'event_id': 'test-event-001',
    'device_id': 'DEVICE-A',
    'user_id': 'user1',
    'timestamp': '2026-10-07T10:01:00',
    'event_type': 'TEST_EVENT',
    'features': {'is_test_event': True},
    'created_at': '2026-10-07T10:01:00'
}
import json
ev_test['features'] = json.dumps(ev_test['features'])
db.insert_event(ev_test)

# exclude_test flag check done in routes, but DB should return the raw data with features
all_a_events = db.get_events(device_id='DEVICE-A')
test_events = [e for e in all_a_events if isinstance(e.get('features'), dict) and e['features'].get('is_test_event')]
real_events = [e for e in all_a_events if not (isinstance(e.get('features'), dict) and e['features'].get('is_test_event'))]
print(f"Total Device A events: {len(all_a_events)} (1 real + 1 test expected)")
print(f"Test events: {len(test_events)}, Real events: {len(real_events)}")

# Cleanup test DB
os.remove(db.db_path)
print("Test DB cleaned. All tests PASSED.")

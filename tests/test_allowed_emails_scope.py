import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database.db import Database

client = TestClient(app)

def test_allowed_emails_database_operations():
    db = Database()
    test_user_id = "usr_test_scope_01"
    
    # 1. Add secondary email
    added = db.add_allowed_email(test_user_id, "secondary.work@gmail.com")
    assert added is True
    
    # 2. Query allowed emails
    allowed = db.get_allowed_emails(test_user_id)
    assert any("secondary.work@gmail.com" in e for e in allowed)
    
    # 3. Query details
    details = db.get_allowed_emails_details(test_user_id)
    assert "additional_emails" in details
    assert any(item["email"] == "secondary.work@gmail.com" for item in details["additional_emails"])
    
    # 4. Remove secondary email
    removed = db.remove_allowed_email(test_user_id, "secondary.work@gmail.com")
    assert removed is True
    
    # 5. Verify removed
    allowed_after = db.get_allowed_emails(test_user_id)
    assert "secondary.work@gmail.com" not in allowed_after

def test_allowed_emails_api_endpoints():
    # GET
    res = client.get("/api/user/allowed-emails?user_id=usr_api_test_01")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "all_monitored" in data

    # POST add email
    add_res = client.post("/api/user/allowed-emails", json={
        "user_id": "usr_api_test_01",
        "email": "my.custom.allowed@gmail.com"
    })
    assert add_res.status_code == 200
    add_data = add_res.json()
    assert "my.custom.allowed@gmail.com" in add_data["all_monitored"]

    # DELETE email
    del_res = client.request("DELETE", "/api/user/allowed-emails", json={
        "user_id": "usr_api_test_01",
        "email": "my.custom.allowed@gmail.com"
    })
    assert del_res.status_code == 200
    del_data = del_res.json()
    assert "my.custom.allowed@gmail.com" not in del_data["all_monitored"]

def test_gmail_inspection_unallowed_mailbox_is_skipped():
    # Send a Gmail inspection for an unapproved mailbox
    res = client.post("/api/browser/event", json={
        "url": "https://mail.google.com",
        "title": "Gmail: Suspicious Email",
        "user_id": "usr_0dbc91212e",
        "device_id": "DEV-TEST",
        "browser_event_type": "GMAIL_INSPECTION",
        "active_mailbox": "completely_unauthorized_stranger@gmail.com",
        "status": "DANGER",
        "reasons": ["Test spoofing"]
    })
    assert res.status_code == 200
    data = res.json()
    # It must be SKIPPED because it's not the registered email (pedapatidhana2@gmail.com) nor in allowed list
    assert data.get("status") == "SKIPPED"
    assert data.get("monitored") is False

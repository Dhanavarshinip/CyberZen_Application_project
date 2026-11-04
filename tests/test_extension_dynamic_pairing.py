import pytest
from backend.database.db import Database
from backend.monitoring.windows_notifier import show_threat_alert_popup
from unittest.mock import patch

def test_dynamic_active_pairing_without_file(tmp_path):
    # Set up temporary db
    test_db_path = str(tmp_path / "test_cyberthreat.db")
    db = Database(test_db_path)
    
    # Check default when no settings exist
    pairing = db.get_active_pairing()
    assert pairing is None
    
    # Save active pairing
    db.set_active_pairing(
        email="student@univ.edu",
        user_id="usr-12345",
        device_id="dev-desktop"
    )
    
    # Verify retrieval
    pairing = db.get_active_pairing()
    assert pairing is not None
    assert pairing["email"] == "student@univ.edu"
    assert pairing["user_id"] == "usr-12345"
    assert pairing["device_id"] == "dev-desktop"

def test_fallback_to_most_recent_user(tmp_path):
    test_db_path = str(tmp_path / "test_cyberthreat.db")
    db = Database(test_db_path)
    
    # Create user
    user = db.create_user(
        email="auto_paired@cyberthreat.org",
        password="ValidPassword123!",
        name="Auto User"
    )
    assert user["email"] == "auto_paired@cyberthreat.org"
    
    # Verify fallback retrieval
    recent = db.get_most_recent_user()
    assert recent is not None
    assert recent["email"] == "auto_paired@cyberthreat.org"

def test_threat_alert_popup_fallback():
    # Verify show_threat_alert_popup can be called without exception
    with patch("subprocess.Popen") as mock_popen:
        mock_popen.return_value = None
        result = show_threat_alert_popup(
            title="CRITICAL THREAT DETECTED",
            file_name="C:\\Users\\User\\Downloads\\trojan.exe",
            status="DANGEROUS",
            reasons=["Double extension detected", "EICAR test string"]
        )
        assert result is True
        assert mock_popen.called

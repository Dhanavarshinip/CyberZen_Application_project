"""
Online/Offline Synchronization Engine for CyberThreat AI System.

Handles resilient telemetry collection under intermittent network connectivity:
- Local SQLite queueing for offline events
- Idempotent deduplication using unique event_ids
- Preserves original timestamp and records sync timestamp
- Automatic retry mechanism with backoff for failed sync attempts
- Real-time online/offline connectivity toggle & state machine
"""

from typing import Dict, Any, List, Optional, Tuple
import time
from datetime import datetime, timezone


class SyncEngine:
    """
    Manages event queueing, deduplication, retry tracking, and batch synchronization.
    """
    
    def __init__(self, db_manager, max_retries: int = 3):
        """
        Args:
            db_manager: Central/Local SQLite database manager instance
            max_retries: Maximum synchronization attempts before marking FAILED
        """
        self.db = db_manager
        self.max_retries = max_retries
        self._is_online = True  # Default to online mode
        self.total_duplicates_prevented = 0
        self.last_sync_latency_ms = 0.0

    @property
    def is_online(self) -> bool:
        return self._is_online

    def set_connectivity(self, online: bool):
        """Allows dynamic toggling between online and offline states for research and testing."""
        self._is_online = bool(online)

    def queue_offline_event(self, event: Dict[str, Any]) -> bool:
        """
        Queues an event locally when operating in offline mode.
        """
        if not event.get("event_id"):
            import uuid
            event["event_id"] = str(uuid.uuid4())
            
        event["sync_status"] = "PENDING"
        return self.db.enqueue_sync_event(event)

    def process_sync_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Processes a batch of events synced from an offline agent or local queue.
        Implements strict idempotency / duplicate prevention.
        Preserves original timestamp and adds synchronized_at timestamp.
        """
        received_count = len(events)
        processed_count = 0
        duplicate_count = 0
        failed_count = 0
        synced_ids = []
        
        t0 = time.perf_counter()
        now_iso = datetime.now(timezone.utc).isoformat()
        
        # Sort events chronologically before ingesting
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))
        
        for ev in sorted_events:
            event_id = ev.get("event_id")
            if not event_id:
                failed_count += 1
                continue
                
            # Check duplicate vs local pending transition
            existing = self.db.get_event(event_id)
            if existing and existing.get("sync_status") in ("SYNCHRONIZED", "SYNCED"):
                duplicate_count += 1
                self.db.update_sync_status(event_id, "SYNCHRONIZED", synchronized_at=now_iso)
                continue
            elif existing:
                # Event was queued locally in SQLite with PENDING status.
                # Transition it to SYNCHRONIZED without re-inserting or counting as duplicate.
                processed_count += 1
                synced_ids.append(event_id)
                self.db.update_sync_status(event_id, "SYNCHRONIZED", synchronized_at=now_iso)
                continue
                
            try:
                # Mark sync fields
                ev["sync_status"] = "SYNCHRONIZED"
                ev["synchronized_at"] = now_iso
                
                # Save into permanent event table
                saved = self.db.save_event(ev)
                if saved:
                    processed_count += 1
                    synced_ids.append(event_id)
                    self.db.update_sync_status(event_id, "SYNCHRONIZED", synchronized_at=now_iso)
                else:
                    failed_count += 1
                    self.db.increment_sync_retry(event_id, max_retries=self.max_retries)
            except Exception as e:
                failed_count += 1
                self.db.increment_sync_retry(event_id, max_retries=self.max_retries)

        self.total_duplicates_prevented += duplicate_count
        self.last_sync_latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        return {
            "status": "success",
            "received_count": received_count,
            "processed_count": processed_count,
            "duplicate_count": duplicate_count,
            "failed_count": failed_count,
            "synced_ids": synced_ids,
            "server_time": now_iso
        }

    def sync_pending_queue(self) -> Dict[str, Any]:
        """
        Extracts all PENDING items from local sync queue and attempts ingestion.
        Used when transitioning from offline to online.
        """
        if not self._is_online:
            return {
                "status": "offline",
                "message": "Sync aborted: Engine currently configured in OFFLINE mode.",
                "pending_count": self.db.get_pending_sync_count()
            }
            
        pending_events = self.db.get_pending_sync_events(limit=500)
        if not pending_events:
            return {
                "status": "up_to_date",
                "processed_count": 0,
                "pending_count": 0
            }
            
        return self.process_sync_batch(pending_events)

"""
CloudGuard Lightweight Scan Scheduler
Supports configurable recurring automated scanning (Daily, Weekly, Manual) in background thread.
"""
import threading
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

logger = logging.getLogger("cloudguard.scheduler")


class ScanScheduler:
    def __init__(self):
        self.mode = "MANUAL"  # "MANUAL", "DAILY", "WEEKLY"
        self.enabled = False
        self.interval_seconds = 86400  # Default 24 hours
        self.last_run: Optional[str] = None
        self.next_run: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

    def set_schedule(self, mode: str, enabled: bool = True) -> Dict[str, Any]:
        with self._lock:
            mode_upper = mode.upper().strip()
            if mode_upper == "DAILY":
                self.mode = "DAILY"
                self.interval_seconds = 86400
                self.enabled = enabled
            elif mode_upper == "WEEKLY":
                self.mode = "WEEKLY"
                self.interval_seconds = 604800
                self.enabled = enabled
            else:
                self.mode = "MANUAL"
                self.interval_seconds = 0
                self.enabled = False

            if self.enabled:
                next_dt = datetime.now() + timedelta(seconds=self.interval_seconds)
                self.next_run = next_dt.strftime("%Y-%m-%d %H:%M:%S")
                if not self._running:
                    self.start()
            else:
                self.next_run = None

        return self.get_status()

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "enabled": self.enabled,
                "mode": self.mode,
                "interval_seconds": self.interval_seconds,
                "last_run": self.last_run,
                "next_run": self.next_run,
            }

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info(f"CloudGuard Scheduler started (Mode: {self.mode})")

    def _loop(self):
        while self._running:
            time.sleep(30)
            with self._lock:
                if not self.enabled or self.mode == "MANUAL":
                    continue
                if self.next_run:
                    try:
                        next_dt = datetime.strptime(self.next_run, "%Y-%m-%d %H:%M:%S")
                        if datetime.now() >= next_dt:
                            # Trigger scheduled scan
                            logger.info("Executing scheduled security scan...")
                            from scanner.main_scanner import run_full_scan
                            run_full_scan()
                            self.last_run = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            next_dt = datetime.now() + timedelta(seconds=self.interval_seconds)
                            self.next_run = next_dt.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception as e:
                        logger.error(f"Error in scheduler execution: {e}")


# Singleton scheduler instance
scheduler = ScanScheduler()

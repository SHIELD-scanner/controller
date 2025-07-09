import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any

try:
    from kubernetes import client, watch

    KUBERNETES_AVAILABLE = True
except ImportError:
    KUBERNETES_AVAILABLE = False


class FalcoAlertConsumer:
    def __init__(
        self,
        mongo_db,
        cluster_name: str,
        logger: logging.Logger,
        namespace: str = "falco-system",
    ):
        self.db = mongo_db
        self.cluster_name = cluster_name
        self.logger = logger
        self.namespace = namespace
        self.running = False
        self._thread = None

    def sync_alert_to_mongo(self, alert: Dict[str, Any]):
        """Store Falco alert in MongoDB"""
        doc = {
            "_event_type": "FALCO_ALERT",
            "_resource_type": "falco_alert",
            "_cluster": self.cluster_name,
            "_timestamp": datetime.now(timezone.utc),
            "_priority": alert.get("priority", "Unknown"),
            "_rule": alert.get("rule", "Unknown"),
            "_output": alert.get("output", ""),
            "data": alert,
        }

        # Generate a unique ID for the alert
        alert_id = f"{alert.get('time', '')}-{alert.get('rule', '')}-{hash(alert.get('output', ''))}"
        doc["_alert_id"] = alert_id

        self.db["falco_alerts"].insert_one(doc)
        self.logger.info(
            f"Stored Falco alert: {alert.get('rule', 'Unknown')} - {alert.get('priority', 'Unknown')}"
        )

    def parse_falco_log_line(self, line: str) -> Dict[str, Any]:
        """Parse a Falco log line and extract alert information"""
        try:
            # Check if this is a JSON formatted alert
            if line.strip().startswith("{"):
                return json.loads(line.strip())

            # Parse plain text format: timestamp priority rule output
            # Example: 21:13:55.123456789: Notice Unexpected connection ...
            parts = line.split(": ", 2)
            if len(parts) >= 3:
                timestamp = parts[0].strip()
                priority_and_rule = parts[1].strip()
                output = parts[2].strip()

                # Split priority and rule
                if " " in priority_and_rule:
                    priority, rule = priority_and_rule.split(" ", 1)
                else:
                    priority = priority_and_rule
                    rule = "Unknown"

                return {
                    "time": timestamp,
                    "priority": priority,
                    "rule": rule,
                    "output": output,
                    "hostname": "unknown",
                }
        except Exception as e:
            self.logger.debug(f"Could not parse Falco log line: {e}")

        return None

    def watch_falco_logs(self):
        """Watch Falco pod logs for alerts"""
        if not KUBERNETES_AVAILABLE:
            self.logger.error("Kubernetes client not available")
            return

        v1 = client.CoreV1Api()
        self.logger.info(f"Starting to watch Falco logs in namespace: {self.namespace}")

        retry_count = 0
        max_retries = 10

        while self.running and retry_count < max_retries:
            try:
                # Get Falco pods
                pods = v1.list_namespaced_pod(
                    namespace=self.namespace,
                    label_selector="app.kubernetes.io/name=falco",
                )

                if not pods.items:
                    self.logger.warning(
                        f"No Falco pods found in namespace {self.namespace}"
                    )
                    time.sleep(30)
                    continue

                # Watch logs from the first available Falco pod
                pod_name = pods.items[0].metadata.name
                self.logger.info(f"Watching logs from Falco pod: {pod_name}")

                w = watch.Watch()
                for event in w.stream(
                    v1.read_namespaced_pod_log,
                    name=pod_name,
                    namespace=self.namespace,
                    container="falco",
                    follow=True,
                    _preload_content=False,
                ):
                    if not self.running:
                        break

                    try:
                        log_line = event
                        if isinstance(log_line, bytes):
                            log_line = log_line.decode("utf-8")

                        # Skip non-alert log lines
                        if not any(
                            priority in log_line
                            for priority in [
                                "Emergency",
                                "Alert",
                                "Critical",
                                "Error",
                                "Warning",
                                "Notice",
                                "Informational",
                                "Debug",
                            ]
                        ):
                            continue

                        alert_data = self.parse_falco_log_line(log_line)
                        if alert_data:
                            self.sync_alert_to_mongo(alert_data)

                    except Exception as e:
                        self.logger.error(f"Error processing Falco log line: {e}")
                        continue

                retry_count = 0  # Reset on successful connection

            except Exception as e:
                retry_count += 1
                self.logger.warning(
                    f"Error watching Falco logs (attempt {retry_count}/{max_retries}): {e}"
                )
                if retry_count < max_retries:
                    time.sleep(min(30, 2**retry_count))
                else:
                    self.logger.error("Max retries reached for Falco log watching")
                    break

        self.logger.info("Falco log watcher stopped")

    def start(self):
        """Start the Falco alert consumer in a background thread"""
        if self._thread and self._thread.is_alive():
            self.logger.warning("Falco alert consumer is already running")
            return

        self.running = True
        self._thread = threading.Thread(target=self.watch_falco_logs, daemon=True)
        self._thread.start()
        self.logger.info("Started Falco alert consumer thread")

    def stop(self):
        """Stop the Falco alert consumer"""
        self.running = False
        if self._thread:
            self._thread.join(timeout=10)
        self.logger.info("Stopped Falco alert consumer")

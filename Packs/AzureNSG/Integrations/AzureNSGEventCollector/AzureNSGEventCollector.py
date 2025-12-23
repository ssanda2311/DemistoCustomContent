import demistomock as demisto
import re
import json
from datetime import datetime, timezone
from typing import Dict, Any, Iterable, List
from azure.storage.blob import BlobServiceClient, BlobPrefix, BlobProperties


def test_module():
    params = demisto.params()
    try:
        conn_str = params.get("connection_string")
        container_name = params.get("container_name")
        blob_service_client = BlobServiceClient.from_connection_string(
            conn_str=conn_str
        )
        container_client = blob_service_client.get_container_client(container_name)
        container_client.get_container_properties()
        return_results("ok")
    except Exception as e:
        return_error(f"Test failed: {str(e)}")


class NSGFlowLogParser:
    def __init__(self, blob_service_client: BlobServiceClient, container_name: str):
        self.client = blob_service_client.get_container_client(container_name)
        self.YEAR_PATTERN = re.compile(r"(.+/)y=\d{4}/$")

    def discover_resources(self, prefix: str = ""):
        for blob in self.client.walk_blobs(name_starts_with=prefix, delimiter="/"):
            if isinstance(blob, BlobPrefix):
                m = self.YEAR_PATTERN.match(blob.name)
                if m:
                    yield m.group(1)
                else:
                    yield from self.discover_resources(prefix=blob.name)

    def list_blobs_for_hours(self, resource_prefix: str, hours_back: int = 0):
        now = datetime.now(tz=timezone.utc)
        ts = now
        hour_marker = ts.strftime("y=%Y/m=%m/d=%d/h=%H/")
        blob_prefix = resource_prefix + hour_marker
        yield from self.client.list_blobs(name_starts_with=blob_prefix)

    # def download_blob_json(self, blob: BlobProperties):
    #     blob_client = self.client.get_blob_client(blob.name)
    #     data = blob_client.download_blob().readall()
    #     if not data or not data.strip():
    #         return blob.name, {}
    #     parsed = json.loads(data)
    #     return blob.name, parsed

    def download_blob_json(
        self, blob: BlobProperties, max_concurrency: int = 6, timeout: int = 300
    ):
        blob_client = self.client.get_blob_client(blob.name)
        downloader = blob_client.download_blob(
            max_concurrency=max_concurrency, timeout=timeout
        )
        data = downloader.readall()
        if not data or not data.strip():
            return blob.name, {}
        parsed = json.loads(data)
        return blob.name, parsed

    def transform_record(self, record):
        ts = record.get("time")
        mac = record.get("macAddress")
        resource_id = record.get("resourceId")
        operation_name = record.get("operationName")
        version = record.get("version")
        flows = record.get("properties", {}).get("flows", [])
        for flow in flows:
            rule = flow.get("rule")
            for group in flow.get("flows", []):
                for tuple_str in group.get("flowTuples", []):
                    fields = tuple_str.split(",")
                    if len(fields) < 13:
                        continue
                    event = {
                        "_raw_log": tuple_str,
                        "ResourceId": resource_id,
                        "OperationName": operation_name,
                        "Version": version,
                        "Rule": rule,
                        "MacAddress": mac,
                        "Timestamp": ts,
                        "SourceIP": fields[1],
                        "DestinationIP": fields[2],
                        "SourcePort": fields[3],
                        "DestinationPort": fields[4],
                        "Protocol": fields[5],
                        "TrafficFlow": "Inbound" if fields[6] == "I" else "Outbound",
                        "TrafficDecision": "Allowed" if fields[7] != "D" else "Denied",
                        "FlowState": fields[8],
                        "PacketsSent": fields[9],
                        "BytesSent": fields[10],
                        "PacketsReceived": fields[11],
                        "BytesRecevied": fields[12],
                    }
                    yield event


def main():
    params = demisto.params()
    command = demisto.command()
    if command == "test-module":
        test_module()
        return
    elif command == "fetch-events":
        container_name = params.get("container_name")
        if not container_name:
            return_error("Please configure 'container_name' in the instance settings.")
        blob_service_client = BlobServiceClient.from_connection_string(
            params.get("connection_string")
        )
        parser = NSGFlowLogParser(blob_service_client, container_name)
        # --- Indexing logic ---
        context = get_integration_context() or {}
        last_index = context.get("index", {})
        if not isinstance(last_index, dict):
            last_index = {}
        MAX_BLOBS_PER_FETCH = 400  # Updated from 15 to 30, 30 to 60 -> 60 to 120 , 120 to 240, 240 to 480, 480 to 580
        MAX_EVENTS_PER_FETCH = 700000  # Adjust as needed
        all_events = []
        blob_count = 0
        batch_full = False
        for resource_prefix in parser.discover_resources():
            if batch_full:
                break
            for blob in parser.list_blobs_for_hours(resource_prefix):
                if blob_count >= MAX_BLOBS_PER_FETCH or batch_full:
                    break
                blob_name, log_json = parser.download_blob_json(blob)
                records = log_json.get("records", [])
                last_processed = last_index.get(blob_name, -1)
                start_index = last_processed + 1
                new_records = records[start_index:]
                for idx, record in enumerate(new_records, start=start_index):
                    for event in parser.transform_record(record):
                        all_events.append(event)
                        if len(all_events) >= MAX_EVENTS_PER_FETCH:
                            batch_full = True
                            break
                    if batch_full:
                        break
                if records:
                    last_index[blob_name] = len(records) - 1
                blob_count += 1
                if batch_full:
                    break
        if all_events:
            send_events_to_xsiam(
                events=all_events,
                vendor=params.get("vendor", "Vendor"),
                product=params.get("product", "AzureNSG"),
                should_update_health_module=True,
            )
        # Persist updated index
        set_integration_context({"index": last_index})
        return_results(f"fetch-events completed. events={len(all_events)}")
    else:
        return_error(f"Unsupported command: {command}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
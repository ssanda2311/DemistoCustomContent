import demistomock as demisto
from datetime import datetime, timedelta, timezone
import urllib3
import json
import requests
import dateparser
from typing import Any, Optional

urllib3.disable_warnings()

class Client(BaseClient):
    """
    Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url, org_id, headers, verify=False, proxy=False):
        self.org_id = org_id

        super().__init__(
            base_url=base_url,
            headers=headers,
            verify=verify,
            proxy=proxy
        )

    def get_events(self, params: dict[str, str]):
        url_suffix = f"/admin/v1/orgs/{self.org_id}/events"
        response = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params,
            resp_type="json",
            ok_codes=[200]
        )

        if response:
            events_data = response.get("data", [])
            meta_data = response.get("meta", [])
            return events_data, meta_data
        else:
            return [], {}

    def test_module(self, params: dict[str, str]):
        url_suffix = f"/admin/v1/orgs/{self.org_id}/events"
        response = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params,
            resp_type="json",
            ok_codes=[200]
        )
        return "ok"



def timestamp_format(timestamp: datetime) -> str:
    """
    Convert datetime format to string format
    """
    time_string = timestamp.strftime("%Y-%m-%dT%H:%M:%S")
    return time_string


def current_utc_milliseconds() -> int:
    """
    Returns current UTC time in milliseconds
    """
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def iso_to_milliseconds(iso_str: str) -> int:
    """
    Convert ISO formatted timestamp string to milliseconds
    """
    dt = datetime.strptime(iso_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    return int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)


def get_last_run(data: list[dict]) -> dict:
    """
    Get the info from the last run, it returns the time to query from
    """
    latest_ts = data[-1]["attributes"]["time"]
    event_ids = [data_item["id"] for data_item in data if data_item["attributes"]["time"] == latest_ts]

    next_run = {
        'time': latest_ts,
        'ids': event_ids
    }

    return next_run


def overlap_exists(data: list[dict], event_ids: list[str]) -> bool:
    """
    Filter to check if events ids from previous fetch are present in new fetch or not
    """
    current_event_ids = [data_item["id"] for data_item in data]
    return any(event_id in current_event_ids for event_id in event_ids)


def deduplicate_events(data: list[dict], event_ids: list[str], fetch_time: str) -> list[dict]:
    """
    Remove duplicate events from the latest fetched events by comparing id and time from
    last fetch
    """
    updated_data = [data_item for data_item in data if
                        data_item["id"] not in event_ids and
                        iso_to_milliseconds(data_item["attributes"]["time"]) >= iso_to_milliseconds(fetch_time)
                    ]
    return updated_data


def should_refetch_events(events: list[dict[str,str]], last_event_ids: list):
    '''
    Function to check if events should be refetched with reduced timestamp
    '''
    if not events:
        return False
    if not last_event_ids:
        return False
    if overlap_exists(events, last_event_ids):
        return False
    
    return True


def fetch_events(client: Client, fetch_limit: int, first_fetch: str, last_run: dict) -> list:
    """
    Format the payload based on event_type i.e. (activities or aggregates) and the fetch the
    API response.
    Perform deduplication of fetched response by comparing with the previous fetch
    """

    # Grace period (ms) to refetch earlier events when overlap is not detected
    refetch_grace_period_ms = 500

    # Get the last execution data
    # time - latest processed event timestamp
    # ids - event IDs that share the latest timestamp
    # cursor - pagination token (if more pages remained)
    last_fetch = last_run.get('time')
    last_event_ids = last_run.get('ids', [])
    cursor = last_run.get('cursor', None)

    # Initialize first fetch timestamp when integration runs for the first time
    if not last_fetch:
        first_fetch_dt = dateparser.parse(first_fetch, settings={'RELATIVE_BASE': datetime.now(timezone.utc)})
        last_fetch = first_fetch_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    # Flag to track whether continuing a paginated fetch cycle of events
    fetch_next_page = False

    params = {
        "limit": fetch_limit,
        "sortOrder": "asc"
    }

    # Determine fetch mode:
    # Use timestamp when (if block):
    #   - If it's first integration fetch
    #   - Or when pagination completed in last fetch cycle
    # Use cursor when (else block): 
    #   - continuing fetch of paginated results
    if cursor is None:
        # Update time filter in API payload
        from_timestamp = iso_to_milliseconds(last_fetch)
        params["from"] = from_timestamp
    else:
        params["cursor"] = cursor
        # set flag to True when using cursor to fetch next page events
        fetch_next_page = True

    # Fetch events from API (returns events and pagination metadata)
    # Extract the pagination cursor from meta data
    events, meta_data = client.get_events(params)
    next_cursor = meta_data.get("next")

    # Apply overlap check and refetch only when:
    #   - Not the integration's first fetch (if last_events_ids are present)
    #   - Events are present in the current fetch
    #   - And continuing paginated events are not fetched in current cycle
    if not fetch_next_page:

        # If no overlapping event IDs are found, refetch with grace window
        # Refetch events when:
        #   - last_events_ids are present
        #   - events are present in the current fetch
        #   - no overlapping events are found (by matching if last_event_ids are present in current fetched events)
        if should_refetch_events(events, last_event_ids):
            # refetch logic
            refetch_time = from_timestamp - refetch_grace_period_ms
            params["from"] = refetch_time

            demisto.updateModuleHealth(f"No overlapping event id found. Refetching with grace time(ms): {refetch_time}")
            demisto.debug(f"No overlapping event id found. Refetching with grace time(ms): {refetch_time}")
            
            # Re-fetch events using adjusted timestamp and get the next cursor from meta data if present
            events, meta_data = client.get_events(params)
            next_cursor = meta_data.get("cursor")

            # Log potential data loss if overlap still does not exist after refetch
            if not overlap_exists(events, last_event_ids):
                demisto.updateModuleHealth(f"Still no overlapping event_id found after refetch with time={refetch_time}. Possible API data loss.")
                demisto.debug(f"Still no overlapping event_id found after refetch with time={refetch_time}. Possible API data loss.")

        # Remove the events with matching events ids as in the last_event_ids
        events = deduplicate_events(events, last_event_ids, last_fetch)

    return events, next_cursor


def test_module(client: Client):
    """
    Function to be called when test button is clicked on integration instance
    """
    # create base paramters to fetch test events from confluence
    params = {
        "limit": 1
    }

    response = client.test_module(params)
    return_results(response)


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('confluence_url')

    # Vendor and Product names
    vendor = "Confluence"
    product = "Admin"

    # API Credentials
    org_id = params.get('credentials', {}).get('identifier')
    api_key = params.get('credentials', {}).get('password')

    use_ssl = params.get('secure', False)
    proxy = params.get('proxy', False)

    headers = {
       "Accept": "application/json",
       "Authorization": f"Bearer {api_key}"
    }

    '''
    Inititate client class object to be used for sending API calls.
    '''
    client = Client(
        base_url=base_url,
        org_id=org_id,
        headers=headers,
        verify=use_ssl,
        proxy=proxy
    )


    command = demisto.command()
    try:
        fetch_limit = params.get("eventFetchLimit", 200)
        first_fetch = params.get("eventFirstFetch", "1 days")

        if command == 'test-module':
            test_module(client)

        elif command == 'fetch-events':
            '''
            Command to be called on each interval as defined in integration instance
            for fetching data and pushing to XSIAM dataset
            '''
            next_run = {}
            last_run = demisto.getLastRun()

            events, next_cursor = fetch_events(client, fetch_limit, first_fetch, last_run)

            # update the next run data
            if events:
                send_events_to_xsiam(events, vendor=vendor, product=product)
                next_run = get_last_run(events)
            else:
                next_run = last_run

            next_run["cursor"] = next_cursor


            demisto.updateModuleHealth({"eventsPulled": (len(events) or 0)})
            demisto.setLastRun(next_run)

    except Exception as e:
        err_msg = f"Error in {get_integration_name()} Integration [{e}]"
        return_error(err_msg, error=e)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
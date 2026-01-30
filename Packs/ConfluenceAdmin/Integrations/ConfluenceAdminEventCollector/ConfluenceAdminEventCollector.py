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
            meta_data = response.get("meta", {})
            return events_data, meta_data
        else:
            return [], {}

    def test_module(self):
        url_suffix = f"/admin/v1/orgs/{self.org_id}/events"
        params = {
            "limit": 1
        }
        response = self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params,
            resp_type="json",
            ok_codes=[200]
        )
        # if request was successfull then return ok else automatically an error will be logged
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


def get_largest_ts_index(data: list[dict]) -> int:
    """
    Function to iterate over all the events the get the index having the largest timestamp
    """
    max_dt = None
    max_index = None
    for index, data_item in enumerate(data):
        data_ts = data_item.get("attributes", {}).get("time")

        if not data_ts:
            continue

        dt = iso_to_milliseconds(data_ts)

        if max_dt is None or dt > max_dt:
            max_dt = dt
            max_index = index
    return max_index


def get_next_run(data: list[dict]) -> dict:
    """
    Get the info for the next run from the currently fetched events, it returns the time to query from
    """
    max_index = get_largest_ts_index(data)
    latest_ts = data[max_index]["attributes"]["time"]
    event_ids = [data_item["id"] for data_item in data if data_item.get("attributes", {}).get("time") == latest_ts]

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


def should_refetch_events(events: list[dict[str,str]], last_event_ids: list) -> bool:
    '''
    Function to check if events should be refetched with adjusted timestamp
    '''
    if not last_event_ids:
        return False
    if overlap_exists(events, last_event_ids):
        return False

    return True


def should_check_duplicates(loop_iterations: int, fetch_continued_events: bool, is_first_fetch: bool, dedup_check: bool) -> bool:
    '''
    Function to check if dedup check to be executed or not.
    '''
    if loop_iterations != 0:
        return False
    if fetch_continued_events:
        return False
    if is_first_fetch:
        return False
    if not dedup_check:
        return False
    
    return True


def fetch_events(client: Client, fetch_limit: int, first_fetch: str, last_run: dict, max_loop_iterations: int, vendor: str, product: str) -> list:
    """
    Format the payload fetch the API response.
    Perform deduplication of fetched response by comparing with the previous fetch
    """

    # Grace period (ms) to refetch earlier events when overlap is not detected
    refetch_grace_period_ms = 10
    
    # Get the last execution data
    # time        - latest processed event timestamp
    # ids         - event IDs that share the latest timestamp
    # last_params - API parameters for continuation fetch when pagination was incomplete;
    #               None on the first execution or when all events were fetched successfully
    last_fetch = last_run.get('time')
    last_event_ids = last_run.get('ids', [])
    last_params = last_run.get("params", {})

    # Indicates whether this is the first fetch cycle of the integration.
    # True only on the initial execution; False for all subsequent runs.
    is_first_fetch = False

    # last_fetch holds the timestamp of the most recent event processed in the previous execution.
    # It will be None on the first execution, in which case we initialize it using first_fetch.
    if not last_fetch:
        is_first_fetch = True
        first_fetch_dt = dateparser.parse(first_fetch, settings={'RELATIVE_BASE': datetime.now(timezone.utc)})
        last_fetch = first_fetch_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    # Determine whether the previous fetch execution was incomplete.
    # If last_params exists, continue fetching using the same API parameters.
    # Otherwise, build new parameters using the last_fetch timestamp.
    if not last_params:
        # Define the time window for the current fetch cycle
        to_timestamp = current_utc_milliseconds()
        from_timestamp = iso_to_milliseconds(last_fetch)

        params = {
            "limit": fetch_limit,
            "sortOrder": "asc",
            "from": from_timestamp,
            "to": to_timestamp
        }

        # Flag set to False to indicate if this is a fresh fetch execution and not a continuation
        fetch_continued_events = False
    else:
        params = {**last_params}

        # Flag set to True to indicate if this fetch is continuing from a previous incomplete cycle
        fetch_continued_events = True
    

    # Track number of fetch loop iterations to prevent infinite pagination
    loop_iterations = 0

    # Local copy of last execution context for updates during fetch cycle
    integration_context = {**last_run}

    # Flag to determine whether deduplication check to be done
    dedup_check = True

    while True:
        # Flag to determine whether pagination loop should terminate
        exit_loop = False
        fetch_params = {**params}

        # Fetch events from API (returns events and pagination metadata)
        # Extract the pagination cursor from meta data
        events, meta_data = client.get_events(fetch_params)
        next_cursor = meta_data.get("next")

        if events:
            # Perform deduplication in following cases 
            # When it is the first loop iteration
            # When pagination events are not fetched 
            # When it is not the integration's first execution
            if should_check_duplicates(loop_iterations, fetch_continued_events, is_first_fetch, dedup_check):
                dedup_check = False

                # If no overlapping event IDs are found, refetch with grace window
                # Refetch events when:
                #   - last_events_ids are present
                #   - events are present in the current fetch
                #   - no overlapping events are found (by matching if last_event_ids are present in current fetched events)
                if should_refetch_events(events, last_event_ids):
                    refetch_time = params["from"] - refetch_grace_period_ms
                    params["from"] = refetch_time

                    demisto.updateModuleHealth(f"No overlapping event id found for api parameters: {fetch_params}. Refetching with grace time(ms): {refetch_time}")
                    demisto.debug(f"No overlapping event id found for api parameters: {fetch_params}. Refetching with grace time(ms): {refetch_time}")
                    
                    # Re-fetch events with adjusted timestamp window
                    events, meta_data = client.get_events(params)
                    next_cursor = meta_data.get("cursor")
                    
                    # Log potential data loss if overlap is still missing
                    # after fetching events with adjusted timestamp
                    if not overlap_exists(events, last_event_ids):
                        demisto.updateModuleHealth(f"Still no overlapping events found for api parameters: {params} with refetch with time={refetch_time}. Possible API data loss.")
                        demisto.debug(f"Still no overlapping events found for api parameters: {params} with refetch with time={refetch_time}. Possible API data loss.")

                # Remove events already processed in the previous execution
                events = deduplicate_events(events, last_event_ids, last_fetch)

            # Get next fetch state from latest processed events
            integration_context = get_next_run(events) if events else {**last_run}

            # Continue pagination if cursor is provided
            if next_cursor:
                params["cursor"] = next_cursor
            else:
                params = {}
                exit_loop = True

            # Update parameters in dict to be updated in integration context
            integration_context["params"] = params

            send_events_to_xsiam(events, vendor=vendor, product=product, should_update_health_module=True)

        else:
            # If no events are fetched then clear parameters and exit the loop
            integration_context["params"] = {}
            exit_loop = True

        # Update fetch state for the next integration execution
        demisto.setLastRun(integration_context)

        # Increment loop counter to handle infinite pagination fetch cycles
        loop_iterations += 1

        # Exit the look if pagination completed 
        # or loop iteration exceeds the max execution as set in integraiotn instance
        if loop_iterations >= max_loop_iterations or exit_loop:
            break



def main() -> None:
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
    max_iterations = arg_to_number(params.get('maxLoopIterations', "10"))

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
            return_results(client.test_module())

        elif command == 'fetch-events':
            '''
            Command to be called on each interval as defined in integration instance
            for fetching data and pushing to XSIAM dataset
            '''
            last_run = demisto.getLastRun()

            fetch_events(client, fetch_limit, first_fetch, last_run, max_iterations, vendor, product)

    except Exception as e:
        err_msg = f"Error in {get_integration_name()} Integration [{e}]"
        return_error(err_msg, error=e)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
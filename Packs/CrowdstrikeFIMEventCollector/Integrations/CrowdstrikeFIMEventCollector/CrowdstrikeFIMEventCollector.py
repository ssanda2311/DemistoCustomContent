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

    def __init__(self, base_url, client_id, client_secret, headers, verify=False, proxy=False):
        self.client_id = client_id
        self.client_secret = client_secret
        self.headers = headers

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy
        )

    def get_auth_token(self):
        """
        Returns a valid Bearer token.
        If the access token has expired, sends API request to generate a new Bearer token else
        return the existing bearer token from integration context
        """
        token_expiry_buffer_seconds = 120  # 2 minutes before token expiry
        millisecond_in_second = 1000  # multiplication factor to convert seconds to milliseconds

        previous_token = get_integration_context()

        if previous_token.get('access_token') and previous_token.get('expiry_time') > date_to_timestamp(datetime.now()):
            demisto.debug("Fetching the access token from integration context")
            return "Bearer " + previous_token['access_token']
        else:
            demisto.debug("Api request to create a new access token")
            result = self.generate_auth_token()

            expiry_time = date_to_timestamp(datetime.now())
            expiry_time += (result['expires_in'] - token_expiry_buffer_seconds) * millisecond_in_second
            token_context = {
                'access_token': result.get('access_token'),
                'expiry_time': expiry_time
            }
            set_integration_context(token_context)
            return "Bearer " + result.get('access_token')

    def generate_auth_token(self):
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials"
        }

        response = self._http_request(
            'POST',
            '/oauth2/token',
            headers=headers,
            data=payload,
            ok_codes=[201]
        )
        return response

    def get_file_changes(self, params):
        updated_headers = {**self.headers, "Authorization": self.get_auth_token()}
        response = self._http_request(
            'GET',
            '/filevantage/queries/changes/v3',
            headers=updated_headers,
            params=params,
            resp_type="response",
            ok_codes=[200]
        )

        if response.status_code == 200:
            response = response.json()
            incidents = response.get("resources", [])
            return incidents
        else:
            return []

    def get_file_change_details(self, params):
        updated_headers = {**self.headers, "Authorization": self.get_auth_token()}
        response = self._http_request(
            'GET',
            '/filevantage/entities/changes/v2',
            headers=updated_headers,
            params=params,
            resp_type="response",
            ok_codes=[200]
        )

        if response.status_code == 200:
            response = response.json()
            incidents = response.get("resources", [])
            return incidents
        else:
            return []

    def test_module(self, params):
        updated_headers = {**self.headers, "Authorization": self.get_auth_token()}
        response = self._http_request(
            'GET',
            '/filevantage/queries/changes/v3',
            headers=updated_headers,
            params=params,
            ok_codes=[200]
        )
        return response


def format_timestamp_str(timestamp_str: str) -> str:
    """
    Format ISO formatted datetime string to custom format as %Y-%m-%d %H:%M:%S.%f
    """
    dt = datetime.fromisoformat(timestamp_str)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def reduce_timestamp_factor(timestamp_str):
    """
    Reduce REFETCH_GRACE_PERIOD_SEC seconds from the timestamp and
    format the ISO datetime string to custom format as %Y-%m-%d %H:%M:%SZ
    """
    refetch_grace_period_sec = 1 # seconds to reduce from last fetch time for refetching the events

    dt = datetime.fromisoformat(timestamp_str)
    new_dt = dt - timedelta(seconds=refetch_grace_period_sec)
    return new_dt.strftime("%Y-%m-%d %H:%M:%SZ")


def convert_timestamp_str_to_dt(timestamp_str):
    """
    Convert timestmap string to datetime object
    """
    dt = datetime.fromisoformat(timestamp_str)
    return dt


def current_utc_isoformat() -> str:
    """
    Returns current UTC timestmap string in format as %Y-%m-%d %H:%M:%S.%f
    """
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_last_run(data: list[dict]) -> dict:
    """
    Get the info from the last run, it returns the time to query from and the last fetched incident ids
    """
    latest_ts = data[-1]["action_timestamp"]
    incident_ids = [data_item["id"] for data_item in data if data_item["action_timestamp"] == latest_ts]

    next_run = {
        'action_timestamp': latest_ts,
        'incident_ids': incident_ids
    }
    return next_run


def deduplicate_incidents(data: list[dict], incidents_ids: list[str], fetch_time: str) -> list[dict]:
    """
    Remove duplicate incidents from the latest fetched incidents by comparing incident id and createdAt from
    last fetch
    """
    updated_data = [data_item for data_item in data if
                        data_item["id"] not in incidents_ids and
                        convert_timestamp_str_to_dt(data_item["action_timestamp"]) >= convert_timestamp_str_to_dt(fetch_time)
                    ]

    return updated_data


def overlap_exists(current_incident_ids: list[str], prev_incidents_ids: list[str]) -> bool:
    """
    Filter to check if incident ids from previous fetch are present in new fetch or not
    """
    return any(incident_id in current_incident_ids for incident_id in prev_incidents_ids)


def get_high_volume_query_changes(client: Client, limit: int, start_timestamp: str) -> list[str]:
    """
    Create API filter parameters to get the FIM ids.
    """
    filter_query = f"action_timestamp:>='{start_timestamp}'+action_timestamp:<='{current_utc_isoformat()}'"
    params = {
        'limit': limit,
        'sort': 'action_timestamp|asc',
        'filter': filter_query
    }

    fim_ids = client.get_file_changes(params)
    return fim_ids


def get_query_change_details(client: Client, change_ids: list[str]) -> list[dict]:
    """
    Returns the complete change details for file change ids if any change_ids are found
    else return empty list
    """
    if change_ids:
        params = {
            "ids": change_ids
        }
        change_details = client.get_file_change_details(params)
        return change_details
    else:
        return []


def fetch_events(client: Client, fetch_limit: int, first_fetch: str, last_run: dict) -> list[dict]:
    """
    Format the payload and the fetch the API response.
    Perform deduplication of fetched response by comparing with the previous fetch
    """
    last_fetch = last_run.get('action_timestamp')
    last_incident_ids = last_run.get('incident_ids', [])

    if not last_fetch:
        first_fetch_dt = dateparser.parse(first_fetch, settings={'RELATIVE_BASE': datetime.now(timezone.utc)})

        if first_fetch_dt.tzinfo is None:
            first_fetch_dt = first_fetch_dt.replace(tzinfo=timezone.utc)
        last_fetch = first_fetch_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Get the change ids reported after last fetch timestamp till current time
    change_ids = get_high_volume_query_changes(client, limit=fetch_limit, start_timestamp=last_fetch)

    '''
    Check if refetch is required based on following parameters:
    - If incident ids are fetched in current run
    - If incident ids are present from last fetch
    - If no overlapping incidents are found
    '''
    if change_ids and last_incident_ids and not overlap_exists(change_ids, last_incident_ids):
        # refetch logic
        refetch_time = reduce_timestamp_factor(last_fetch)

        demisto.updateModuleHealth(f"No overlapping incident ids found. Refetching high volume query change ids with grace time(seconds): {refetch_time}")
        demisto.debug(f"No overlapping incident id found. Refetching high volume query chagne ids with grace time(seconds): {refetch_time}")
        change_ids = get_high_volume_query_changes(client, limit=fetch_limit, start_timestamp=refetch_time)

        if not overlap_exists(change_ids, last_incident_ids):
            demisto.updateModuleHealth("Still no overlapping incident ids found after refetch. Possible API data loss.")
            demisto.debug("Still no overlapping incident ids found after refetch. Possible API data loss.")

    # Get the complete details for the change ids retrieved
    incidents = get_query_change_details(client, change_ids)

    incidents = deduplicate_incidents(incidents, last_incident_ids, last_fetch)
    return incidents


def test_module(client: Client):
    """
    Function to be called when test button is clicked on integration instance
    """
    params = {
        "limit": 1
    }

    incidents = client.test_module(params)
    if incidents:
        return_results('ok')


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('cs_fim_url')

    # Vendor and Product name for dataset
    vendor = "Crowdstrike"
    product = "FIM"

    # API Credentials
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')

    use_ssl = params.get('secure', False)
    proxy = params.get('proxy', False)
    headers = {
       "accept": "application/json"
    }

    '''
    Inititate client class object to be used for sending API calls.
    '''
    client = Client(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        headers=headers,
        verify=use_ssl,
        proxy=proxy
    )


    command = demisto.command()
    try:
        fetch_limit = params.get("eventFetchLimit", 100)
        first_fetch = params.get("eventFirstFetch", "1 days")

        if command == 'test-module':
            test_module(client)

        elif command == 'fetch-events':
            '''
            Command to be called on each interval as defined in integration instance
            for fetching data and pushing to XSIAM dataset
            '''
            next_run = {}
            last_run = demisto.getLastRun() or {}

            incidents = fetch_events(client, fetch_limit, first_fetch, last_run)

            if incidents:
                send_events_to_xsiam(incidents, vendor=vendor, product=product)
                next_run = get_last_run(incidents)

            # If next run is empty then reset last run as next run
            if not next_run:
                next_run = last_run

            demisto.updateModuleHealth({"eventsPulled": (len(incidents) or 0)})
            demisto.setLastRun(next_run)

    except Exception as e:
        err_msg = f"Error in {get_integration_name()} Integration [{e}]"
        return_error(err_msg, error=e)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
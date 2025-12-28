import demistomock as demisto
from datetime import datetime, timedelta, timezone
import urllib3
import requests
import dateparser
from typing import Any, Optional, Union

urllib3.disable_warnings()

class AuthClient(BaseClient):
    """
    Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """
    def __init__(self, client_id, client_secret, app_id, scope, verify=False, proxy=False):
        self.app_id = app_id
        self.auth_payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope
        }

        super().__init__(
            base_url="https://aao4790.id.cyberark.cloud",
            verify=verify,
            proxy=proxy
        )

    def generate_auth_token(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        response = self._http_request(
            'POST',
            f'/OAuth2/Token/{self.app_id}',
            headers=headers,
            data=self.auth_payload,
            ok_codes=[200]
        )
        return response


class Client(BaseClient):
    """
    Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url, client_id, client_secret, app_id, scope, headers, verify=False, proxy=False):
        self.oauth = AuthClient(client_id, client_secret, app_id, scope, verify, proxy)
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
        token_expiry_buffer_seconds = 300  # 5 minutes before token expiry
        millisecond_in_second = 1000  # multiplication factor to convert seconds to milliseconds

        previous_token = get_integration_context()

        if previous_token.get('access_token') and previous_token.get('expiry_time') > date_to_timestamp(datetime.now()):
            demisto.debug("Fetching the access token from integration context")
            return "Bearer " + previous_token['access_token']
        else:
            demisto.debug("Api request to create a new access token")
            result = self.oauth.generate_auth_token()

            expiry_time = date_to_timestamp(datetime.now())

            '''
            Create token expiry time in miliseconds by reducing 'token_expiry_buffer_seconds' from the
            original expiry time received from auth token response and multiply by 'millisecond_in_second'
            to convert into miliseconds
            '''
            expiry_time += (result['expires_in'] - token_expiry_buffer_seconds) * millisecond_in_second
            token_context = {
                'access_token': result.get('access_token'),
                'expiry_time': expiry_time
            }
            set_integration_context(token_context)
            return "Bearer " + result.get('access_token')

    def cyberark_stream_create_query(self, payload):
        headers = {
            **self.headers,
            "Authorization": self.get_auth_token()
        }

        response = self._http_request(
            'POST',
            '/api/audits/stream/createQuery',
            headers=headers,
            json_data=payload,
            resp_type="json",
            ok_codes=[200]
        )
        return response.get("cursorRef")

    def cyberark_stream_query_results(self, cursor_ref):
        headers = {
            **self.headers,
            "Authorization": self.get_auth_token()
        }

        response = self._http_request(
            'POST',
            '/api/audits/stream/results',
            headers=headers,
            json_data={"cursorRef": cursor_ref},
            resp_type="response",
            ok_codes=[200]
        )

        if response.status_code == 200:
            response = response.json()
            return response
        else:
            return {}

    def test_module(self):
        result = self.oauth.generate_auth_token()
        return result


def convert_timestamp_str_to_dt(timestamp_str):
    """
    Convert timestmap string to datetime object
    """
    dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return dt


def convert_timestamp_dt_to_str(timestamp_dt):
    """
    Convert datetime timestmap to string
    """
    return timestamp_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")


def current_utc() -> int:
    """
    Returns current UTC timestmap string in format as %Y-%m-%dT%H:%M:%S.%f
    """
    now = datetime.now(timezone.utc)
    return convert_timestamp_dt_to_str(now)


def get_application_code(service_name: str):
    """
    Returns the mapped application code for a  service name
    """
    service_application_mapping = {
        'Conjur Cloud': 'CSM',
        'Identity': 'IDP',
        'Privilege Cloud': 'PAM',
        'Secure Infrastructure Access': 'SIA',
        'Secrets Hub': 'SHSM',
        'Secure Cloud Access': 'SCA'
    }

    application_code = service_application_mapping.get(service_name)
    if not application_code:
        raise DemistoException(f'Invalid service name: {service_name}. Please select a valid service name.')
    return application_code


def reduce_ms(timestamp, factor):
    """
    Reduce x milisecond from the timestamp
    """
    dt = convert_timestamp_str_to_dt(timestamp)

    # Subtract 1 millisecond
    new_dt = dt - timedelta(milliseconds=factor)
    return convert_timestamp_dt_to_str(new_dt)


def convert_timestamp_to_dt(timestamp: int):
    """
    Convert unix timestamp value to date time formatted value
    """
    dt = datetime.fromtimestamp(timestamp/1000, tz=timezone.utc)
    return dt


def get_last_run(data: list[dict]) -> dict:
    """
    Get the info from the last run, it returns the time to query from and the last fetched incident ids
    """
    latest_ts = data[-1]["timestamp"]
    # convert event timestmap in milliseconds to datetime str format YYYY-MM-DDTHH:MM:SS.f
    latest_ts_dt = convert_timestamp_dt_to_str(convert_timestamp_to_dt(latest_ts))

    event_ids = [data_item["uuid"] for data_item in data if data_item["timestamp"] == latest_ts]

    next_run = {
        'timestamp': latest_ts_dt,
        'uuid': event_ids
    }
    return next_run


def deduplicate_events(events: list[dict], event_ids: list[str], fetch_time: str) -> list[dict]:
    """
    Remove duplicate events from the latest fetched events by comparing event uuid and timestamp from
    last fetch
    """
    updated_events = [event for event in events if
                        event["uuid"] not in event_ids and
                        convert_timestamp_to_dt(event["timestamp"]) >= convert_timestamp_str_to_dt(fetch_time)
                    ]

    return updated_events


def overlap_exists(events: list[dict], event_ids: list[str]) -> bool:
    """
    Filter to check if events ids from previous fetch are present in new fetch or not
    """
    current_event_ids = [event["uuid"] for event in events]
    return any(event_id in current_event_ids for event_id in event_ids)


def sort_events(events, order="asc"):
    if order == "asc":
        return sorted(events, key=lambda x: x["timestamp"])
    else:
        return sorted(events, key=lambda x: x["timestamp"], reverse=True)


def create_query_payload(fetch_limit, from_ts, to_ts, application_code):
    """
    """
    payload = {
        "query": {
            "pageSize": fetch_limit,
            "selectedFields": ["arrivalTimestamp"],
            "filterModel": {
                "date": {
                    "dateFrom": from_ts,
                    "dateTo": to_ts
                },
                "applicationCode": [{
                    "op": "include",
                    "params": [
                        application_code
                    ],
                    "filter_type": 7
                }],
            }
        }
    }
    return payload


def fetch_events(client: Client, fetch_limit: int, first_fetch: str, last_run: dict, application_code) -> tuple[list[dict], Union[str, None]]:
    """
    Format the payload and the fetch the API response.
    Perform deduplication of fetched response by comparing with the previous fetch
    """
    last_fetch = last_run.get('timestamp')
    last_event_ids = last_run.get('uuid', [])
    last_cursor_ref = last_run.get('cursor_ref')
    perform_dedup = True

    if not last_fetch:
        first_fetch_dt = dateparser.parse(first_fetch, settings={'RELATIVE_BASE': datetime.now(timezone.utc)})

        if first_fetch_dt.tzinfo is None:
            first_fetch_dt = first_fetch_dt.replace(tzinfo=timezone.utc)
        first_fetch = convert_timestamp_dt_to_str(first_fetch_dt)

    '''
    Check if there is next page in the previous fetch
    by fetching the results from last_cursor.
    '''
    if not last_cursor_ref:
        if not last_fetch:
            last_fetch = first_fetch
            is_initial_fetch = True
        else:
            last_fetch = reduce_ms(last_fetch, factor=1)
            is_initial_fetch = False

        # create payload for the create query api request
        to_date = current_utc()

        duplicate_events_found = False  # flag to check if duplicate events are found
        max_lookback = 5  # max number of lookback iterations
        lookback_count = 0  # run loop for max_lookback iterations to fetch the overlapping events
        events_data = []

        '''
        If it not the initial fetch then loop and check for overlapping events
        else send only single api call to fetch the events.
        '''
        if not is_initial_fetch:
            while lookback_count < max_lookback:
                payload = create_query_payload(fetch_limit, last_fetch, to_date, application_code)
                cursor_ref = client.cyberark_stream_create_query(payload)
                events = client.cyberark_stream_query_results(cursor_ref)
                events_data = events.get("data", [])
                events_data = sort_events(events_data)

                # check if overlapping events found
                if events_data:
                    if overlap_exists(events_data, last_event_ids):
                        # Found overlapping events
                        duplicate_events_found = True
                        break
                    
                    '''
                    If no overlapping events are found then further reduce the timestamp by 1000 miliseconds 
                    and fetch the events.
                    '''
                    last_fetch = reduce_ms(last_fetch, factor=1000)
                    lookback_count += 1
                else:
                    break
            
            '''
            If the while loop all iterations execution finished but still 
            no overlapping events are found.
            Then, raise error and it is possibly a api data loss only, not an error from 
            integration code.
            '''
            if lookback_count == max_lookback and not events_data:
                demisto.updateModuleHealth(
                    f"No overlapping events found for timeframe: {last_fetch} to {to_date}, application code: {application_code}. Possible API data loss."
                )
                demisto.debug(
                    f"No overlapping events found for timeframe: {last_fetch} to {to_date}, application code: {application_code}. Possible API data loss."
                )
        else:
            payload = create_query_payload(fetch_limit, last_fetch, to_date, application_code)
            cursor_ref = client.cyberark_stream_create_query(payload)
            events = client.cyberark_stream_query_results(cursor_ref)
            events_data = events.get("data", [])
            events_data = sort_events(events_data)
            perform_dedup = False

    else:
        # Continuation using existing cursor
        events = client.cyberark_stream_query_results(last_cursor_ref)
        events_data = events.get("data", [])
        events_data = sort_events(events_data)
        perform_dedup = False

    if perform_dedup and events_data:
        events_data = deduplicate_events(events_data, last_event_ids, last_run.get('timestamp', last_fetch))


    # Set next cursor
    next_cursor = events.get("paging", {}).get("cursor", {}).get("cursorRef") if events_data else None

    return events_data, next_cursor


def test_module(client: Client):
    """
    Function to be called when test button is clicked on integration instance
    """
    response = client.test_module()
    if "access_token" in response:
        return_results("ok")


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('cyberark_url')

    # Vendor and Product name for dataset
    vendor = "Cyber"
    product = "Ark"

    # API Credentials
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    app_id = params.get('app_id')
    api_key = params.get('api_key', {}).get("password")
    scope = params.get('scope', {})

    use_ssl = params.get('secure', False)
    proxy = params.get('proxy', False)

    application_code = get_application_code(params.get('service_name', 'Privilege Cloud'))

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "Accept": "application/json",
    }

    '''
    Inititate client class object to be used for sending API calls.
    '''
    client = Client(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        app_id=app_id,
        scope=scope,
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
            last_run = demisto.getLastRun() or {}

            events, next_cursor = fetch_events(client, fetch_limit, first_fetch, last_run, application_code)

            if events:
                send_events_to_xsiam(events, vendor=vendor, product=f"{product}_{application_code}")
                next_run = get_last_run(events)

            # If next run is empty then reset last run as next run
            if not next_run:
                next_run = last_run

            # update cursor in the context
            next_run["cursor_ref"] = next_cursor

            demisto.updateModuleHealth({"eventsPulled": (len(events) or 0)})
            demisto.setLastRun(next_run)

    except Exception as e:
        err_msg = f"Error in {get_integration_name()} Integration [{e}]"
        return_error(err_msg, error=e)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
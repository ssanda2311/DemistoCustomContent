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
        If the access token has expired, tries to refresh it using the refresh token.
        If that fails, gets a completely new one using client credentials.
        """

        token_expiry_buffer_seconds = 1800  # 30 minutes before token expiry
        millisecond_in_second = 1000  # multiplication factor to convert seconds to milliseconds

        context = get_integration_context()
        access_token = context.get("access_token")
        refresh_token = context.get("refresh_token")
        expiry_time = context.get("expiry_time", 0)
        current_time = date_to_timestamp(datetime.now())

        if access_token and expiry_time > current_time:
            demisto.debug("Using the access token from integration context")
            return f"Bearer {access_token}"

        demisto.debug("Access token missing or expired — attempting refresh.")

        # Refresh token
        result = None
        if refresh_token:
            result = self.refresh_auth_token(refresh_token)
        
        # Generate token using credentials if refresh failed
        if not result:
            demisto.debug("Refresh token invalid or missing — generating new access token.")
            result = self.generate_auth_token()
        
        expiry_time = date_to_timestamp(datetime.now())

        '''
        Create token expiry time in miliseconds by reducing 'token_expiry_buffer_seconds' from the 
        original expiry time received from auth token response and multiply by 'millisecond_in_second' 
        to convert into miliseconds
        '''
        expiry_time += (result['expires_in'] - token_expiry_buffer_seconds) * millisecond_in_second
        token_context = {
            'access_token': result.get('access_token'),
            'expiry_time': expiry_time,
            'refresh_token': result.get('refresh_token')
        }

        set_integration_context(token_context)
        return "Bearer " + result.get('access_token')

    def generate_auth_token(self):
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
            "scope": "*"
        }
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json"
        }

        response = self._http_request(
            'POST', 
            '/v2/apis/auth/oauth/token', 
            headers=headers, 
            data=payload, 
            ok_codes=[200]
        )
        return response

    def refresh_auth_token(self, refresh_token):
        payload = {
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "scope": "*",
            "refresh_token": refresh_token
        }
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json"
        }

        try:
            response = self._http_request(
                'POST', 
                '/v2/apis/auth/oauth/token', 
                headers=headers, 
                data=payload, 
                ok_codes=[200]
            )

            if response.get("access_token"):
                return response
            else:
                return None
        except Exception as e:
            demisto.updateModuleHealth(f"Refresh token failed: {str(e)}")
            return None

    def proofpoint_get_events(self, url_suffix, payload):
        updated_headers = {**self.headers, "Authorization": self.get_auth_token()}
        response = self._http_request(
            'POST',
            url_suffix,
            headers=updated_headers,
            json_data=payload,
            resp_type="response"
        )

        if response.status_code == 200:
            response = response.json()
            events_data = response.get("data", [])
            return events_data
        else:
            return []

    def test_module(self, url_suffix, payload):
        updated_headers = {**self.headers, "Authorization": self.get_auth_token()}
        response = self._http_request(
            'POST',
            url_suffix,
            headers=updated_headers,
            json_data=payload,
            resp_type="response"
        )

        if response.status_code == 200:
            return response.json()
        else:
            return {}


def get_activities_base_payload() -> dict:
    """
    Base payload definition for the Activity events API call.
    """
    return {
        "sort": [
            {
                "event.observedAt": {
                    "order": "asc",
                    "unmapped_type": "boolean"
                }
            },
            {
                "event.id": {
                    "order": "asc",
                    "unmapped_type": "boolean"
                }
            }
        ],
        "filters": {
            "$and": [
                {
                    "$or": [
                    {
                        "$stringIn": {
                        "incident.kind": [
                            "it:platform:incident"
                        ]
                        }
                    }
                    ]
                },
                {
                    "$not": {
                    "$or": [
                        {
                        "$stringIn": {
                            "activity.categories": [
                            "it:internal:agent",
                            "it:internal:agent:start",
                            "it:internal:agent:stop",
                            "it:internal:agent:data-loss",
                            "it:internal:agent:tampering",
                            "it:internal:agent:functionality",
                            "it:internal:agent:informational",
                            "it:internal:agent:lifecycle",
                            "it:internal:agent:offline",
                            "it:internal:agent:metrics",
                            "it:internal:agent:error"
                            ]
                        }
                        }
                    ]
                    }
                },
                {
                    "$not": {
                    "$or": [
                        {
                        "$stringIn": {
                            "audit.kind": [
                            "it:auth-default:authorization:createAuthorizationSet:audit"
                            ]
                        }
                        }
                    ]
                    }
                },
                {
                    "$not": {
                    "$or": [
                        {
                        "$stringIn": {
                            "event.kind": [
                            "it:updater:internal:event"
                            ]
                        }
                        }
                    ]
                    }
                },
                {
                    "$datetimeGE": {
                        "event.observedAt": ""
                    }
                },
                {
                    "$datetimeLT": {
                        "event.observedAt": ""
                    }
                }
            ]
        }
    }

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
    latest_ts = data[-1]["event"]["observedAt"]
    event_ids = [data_item["event"]["id"] for data_item in data if data_item["event"]["observedAt"] == latest_ts]

    next_run = {
        'observed_at': latest_ts,
        'event_ids': event_ids
    }

    return next_run


def overlap_exists(data: list[dict], event_ids: list[str]) -> bool:
    """
    Filter to check if events ids from previous fetch are present in new fetch or not
    """
    current_event_ids = [data_item["event"]["id"] for data_item in data]
    return any(event_id in current_event_ids for event_id in event_ids)


def deduplicate_events(data: list[dict], event_ids: list[str], fetch_time: str) -> list[dict]:
    """
    Remove duplicate events from the latest fetched events by comparing event_ids and observer_at from
    last fetch
    """
    updated_data = [data_item for data_item in data if
                        data_item["event"]["id"] not in event_ids and
                        iso_to_milliseconds(data_item["event"]["observedAt"]) >= iso_to_milliseconds(fetch_time)
                    ]
    return updated_data


def update_time_filters(payload: dict, start_time: Optional[int] = None, end_time: Optional[int] = None) -> dict:
    """
    Update the event.observedAt time filters in API payload for fetching the Aggregates and Activities
    """
    for _filter in payload["filters"]["$and"]:
        if start_time and "$datetimeGE" in _filter:
            _filter["$datetimeGE"]["event.observedAt"] = start_time

        if end_time and "$datetimeLT" in _filter:
            _filter["$datetimeLT"]["event.observedAt"] = end_time
    return payload


def fetch_events(client: Client, event_type: str, fetch_limit: int, first_fetch: str, last_run: dict) -> list:
    """
    Format the payload based on event_type i.e. (activities or aggregates) and the fetch the 
    API response.
    Perform deduplication of fetched response by comparing with the previous fetch
    """
    url_suffix = f"/v2/apis/activity/event-queries?offset=0&limit={fetch_limit}&includes=screenshots&sources=cloud:isolation,email:pps,endpoint:agent,platform:analytics&trackTotalHits=false"
    
    '''
    Number of miliseconds to push back for refetching 
    in case no duplicates are found.
    '''
    refetch_grace_period_ms = 1000 

    last_fetch = last_run.get('observed_at')
    last_event_ids = last_run.get('event_ids', [])

    if not last_fetch:
        first_fetch_dt = dateparser.parse(first_fetch, settings={'RELATIVE_BASE': datetime.now(timezone.utc)})
        last_fetch = first_fetch_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    payload = get_activities_base_payload()  # get the base payload for activities API call

    # Update time filter in API payload
    current_time = current_utc_milliseconds()
    last_fetch_ms = iso_to_milliseconds(last_fetch)
    payload = update_time_filters(payload, last_fetch_ms, current_time)

    # demisto.updateModuleHealth(f"Current time: {current_time}\nLast Fetch: {last_fetch_ms}\nPayload: {json.dumps(payload)}")

    '''
    Aggreagates fetch part is no longer in use
    
    if event_type == "aggregates":
        # Update aggregates to payload
        payload ["aggregates"] = [
            {
                "aggregateName": "verifyAlertBulkActions",
                "sources": [
                    {
                        "type": "terms",
                        "field": "incident.severity",
                        "order": {
                        "_count": "desc"
                        },
                        "size": 100,
                        "missing": ""
                    }
                ]
            },
            {
                "aggregateName": "activity.categories",
                "sources": [
                    {
                        "type": "cardinality",
                        "field": "activity.categories"
                    }
                ]
            },
            {
                "aggregateName": "user.aliases.name",
                "sources": [
                    {
                        "type": "cardinality",
                        "field": "user.aliases.name"
                    }
                ]
            },
            {
                "aggregateName": "histogram",
                "sources": [
                    {
                        "type": "date_histogram",
                        "field": "event.observedAt",
                        "interval": "1080s",
                        "min_doc_count": 0,
                        "extended_bounds": {
                            "min": "2025-09-15T06:04:10.771Z",
                            "max": "2025-09-16T06:04:10.771Z"
                        }
                    }
                ]
            }
        ]
    '''

    '''
    Send api call with url suffix and json payload to 
    get the Activities event data
    '''
    events = client.proofpoint_get_events(url_suffix, payload)

    '''
    Check if refetch is required based on following parameters:
    - If events are fetched in current run
    - If events ids are present from last fetch
    - If no overlapping events are found
    '''
    if events and last_event_ids and not overlap_exists(events, last_event_ids):
        # refetch logic
        refetch_time = last_fetch_ms - refetch_grace_period_ms
        payload = update_time_filters(payload, refetch_time)

        demisto.updateModuleHealth(f"No overlapping event_id found in {event_type}. Refetching with grace time(ms): {refetch_time}")
        demisto.debug(f"No overlapping event_id found in {event_type}. Refetching with grace time(ms): {refetch_time}")
        events = client.proofpoint_get_events(url_suffix, payload)

        if not overlap_exists(events, last_event_ids):
            demisto.updateModuleHealth(f"Still no overlapping event_id found in {event_type} after refetch. Possible API data loss.")
            demisto.debug(f"Still no overlapping event_id found in {event_type} after refetch. Possible API data loss.")

    events = deduplicate_events(events, last_event_ids, last_fetch)
    
    # add event type key to the events: activities/aggreagtes
    for event in events:
        event["event_type"] = event_type

    return events


def test_module(client: Client):
    """
    Function to be called when test button is clicked on integration instance
    """
    payload = get_activities_base_payload()   # get the activities base payload

    '''
    Update time filter in API payload
    Fetch test events for last 24 hours only by using relative time = -86400000
    '''
    payload = update_time_filters(payload, -86400000, current_utc_milliseconds())

    url_suffix = f"/v2/apis/activity/event-queries?offset=0&limit=1&includes=screenshots&sources=cloud:isolation,email:pps,endpoint:agent,platform:analytics&trackTotalHits=false"

    events = client.test_module(url_suffix, payload)

    if events and events.get("_status", {}).get("status") in [200]:
        return_results('ok')


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('proofpoint_url')

    # Vendor and Product names
    vendor = "Proofpoint"
    product = "ITM"

    # API Credentials
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')

    use_ssl = params.get('secure', False)
    proxy = params.get('proxy', False)

    headers = {
       "accept": "application/json",
       "Content-Type":"application/json"
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
        fetch_limit = params.get("eventFetchLimit", 500)
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

            if not last_run:
                activities_last_run = {}
                # aggregates_last_run = {}
            else:
                activities_last_run = last_run.get('activities', {})
                # aggregates_last_run = last_run.get('aggregates', {})

            activities_data = fetch_events(client, 'activities', fetch_limit, first_fetch, activities_last_run)
    
            if activities_data:
                send_events_to_xsiam(activities_data, vendor=vendor, product=product)
                next_run['activities'] = get_last_run(activities_data)
            else:
                next_run['activities'] = last_run.get('activities')
            
            '''
            Commenting the aggregates fetch as it also returns the same events data as activities.
            Along with same event data as activities, aggregates contains some additional information 
            which is not required for XSIAM use case.
            '''
            '''
            aggregates_data = fetch_events(client, 'aggregates', fetch_limit, first_fetch, aggregates_last_run)

            if aggregates_data:
                send_events_to_xsiam(aggregates_data, vendor=vendor, product=product)
                next_run['aggregates'] = get_last_run(aggregates_data)
            else:
                next_run['aggregates'] = last_run.get('aggregates')
            '''

            # demisto.updateModuleHealth({"eventsPulled": (len(activities_data) or 0)})
            demisto.setLastRun(next_run)

    except Exception as e:
        err_msg = f"Error in {get_integration_name()} Integration [{e}]"
        return_error(err_msg, error=e)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
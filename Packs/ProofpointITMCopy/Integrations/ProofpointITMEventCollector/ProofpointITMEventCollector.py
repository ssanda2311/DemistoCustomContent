from datetime import datetime, timedelta, timezone
import urllib3
import json
import requests
import dateparser
from typing import Any


urllib3.disable_warnings()
PROOFPOINT_OAUTH_ENDPOINT = '/v2/apis/auth/oauth/token'
PROOFPOINT_EVENTS_ENDPOINT = '/v2/apis/activity/event-queries'
VENDOR = "Proofpoint"
PRODUCT = "ITM"
REFETCH_GRACE_PERIOD_MS = 1000

class Client(BaseClient):
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
        previous_token = get_integration_context()

        if previous_token.get('access_token') and previous_token.get('expiry_time') > date_to_timestamp(datetime.now()):
            demisto.debug("Fetching the access token from integration context")
            return "Bearer " + previous_token['access_token']
        else:
            result = self.generate_auth_token()
            demisto.debug("Api request to create a new access token")

            expiry_time = date_to_timestamp(datetime.now())
            expiry_time += (result['expires_in'] - 1800) * 1000
            token_context = {
                'access_token': result.get('access_token'),
                'expiry_time': expiry_time
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


def timestamp_format(timestamp):
    time_string = timestamp.strftime("%Y-%m-%dT%H:%M:%S")
    return time_string

def current_utc_milliseconds() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)

def iso_to_milliseconds(iso_str: str) -> int:
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


def overlap_exists(data, event_ids):
    """
    Filter to check if events ids from previous fetch are present in new fetch or not
    """
    current_event_ids = [data_item["event"]["id"] for data_item in data]
    return any(event_id in current_event_ids for event_id in event_ids)


def deduplicate_events(data, event_ids, fetch_time):
    """
    Remove duplicate events from the latest fetched events by comparing event_ids and observer_at from
    last fetch
    """
    updated_data = [data_item for data_item in data if
                        data_item["event"]["id"] not in event_ids and
                        iso_to_milliseconds(data_item["event"]["observedAt"]) >= iso_to_milliseconds(fetch_time)
                    ]
    return updated_data


def get_activities(client, fetch_limit, first_fetch, last_run):
    """
    Fetch ITM events
    """
    url_suffix = f"{PROOFPOINT_EVENTS_ENDPOINT}?offset=0&limit={fetch_limit}&includes=screenshots&sources=cloud:isolation,email:pps,endpoint:agent,platform:analytics&trackTotalHits=false"

    last_fetch = last_run.get('observed_at')
    last_event_ids = last_run.get('event_ids', [])

    if not last_fetch:
        first_fetch_dt = dateparser.parse(first_fetch, settings={'RELATIVE_BASE': datetime.now(timezone.utc)})
        last_fetch = first_fetch_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    payload = {
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
                        "event.observedAt": iso_to_milliseconds(last_fetch)
                    }
                },
                {
                    "$datetimeLT": {
                        "event.observedAt": current_utc_milliseconds()
                    }
                }
            ]
        }
    }

    events = client.proofpoint_get_events(url_suffix, payload)

    if last_event_ids and not overlap_exists(events, last_event_ids):
        # refetch logic
        refetch_time = payload["filters"]["$and"][4]["$datetimeGE"]["event.observedAt"] - REFETCH_GRACE_PERIOD_MS
        payload["filters"]["$and"][4]["$datetimeGE"]["event.observedAt"] = refetch_time

        demisto.updateModuleHealth(f"No overlapping event_id found in activities. Refetching with grace time(ms): {refetch_time}")
        demisto.debug(f"No overlapping event_id found in activities. Refetching with grace time(ms): {refetch_time}")
        events = client.proofpoint_get_events(url_suffix, payload)

        if not overlap_exists(events, last_event_ids):
            demisto.updateModuleHealth("Still no overlapping event_id found in activities after refetch. Possible API data loss.")
            demisto.debug("Still no overlapping event_id found in activities after refetch. Possible API data loss.")


    events = deduplicate_events(events, last_event_ids, last_fetch)
    return events


def get_aggregates(client, fetch_limit, first_fetch, last_run):
    """
    Fetch ITM aggregates events
    """
    url_suffix = f"{PROOFPOINT_EVENTS_ENDPOINT}?offset=0&limit={fetch_limit}&includes=screenshots&sources=cloud:isolation,email:pps,endpoint:agent,platform:analytics&trackTotalHits=false"

    last_fetch = last_run.get('observed_at')
    last_event_ids = last_run.get('event_ids', [])

    if not last_fetch:
        first_fetch_dt = dateparser.parse(first_fetch, settings={'RELATIVE_BASE': datetime.now(timezone.utc)})
        last_fetch = first_fetch_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    payload = {
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
        "aggregates": [
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
                    "event.observedAt": iso_to_milliseconds(last_fetch)
                    }
                },
                {
                    "$datetimeLT": {
                    "event.observedAt": current_utc_milliseconds()
                    }
                }
            ]
        }
    }

    events = client.proofpoint_get_events(url_suffix, payload)

    if last_event_ids and not overlap_exists(events, last_event_ids):
        # refetch logic
        refetch_time = payload["filters"]["$and"][4]["$datetimeGE"]["event.observedAt"] - REFETCH_GRACE_PERIOD_MS
        payload["filters"]["$and"][4]["$datetimeGE"]["event.observedAt"] = refetch_time

        demisto.updateModuleHealth(f"No overlapping event_id found in agregates. Refetching with grace time(ms): {refetch_time}")
        demisto.debug(f"No overlapping event_id found in agregates. Refetching with grace time(ms): {refetch_time}")
        events = client.proofpoint_get_events(url_suffix, payload)

        if not overlap_exists(events, last_event_ids):
            demisto.updateModuleHealth("Still no overlapping event_id found in aggregates after refetch. Possible API data loss.")
            demisto.debug("Still no overlapping event_id found in aggregates after refetch. Possible API data loss.")

    events = deduplicate_events(events, last_event_ids, last_fetch)
    return events


def fetch_events(client: Client, event_type, fetch_limit, first_fetch, last_run):
    if event_type == 'activities':
        events = get_activities(client, fetch_limit, first_fetch, last_run)

    if event_type == 'aggregates':
        events = get_aggregates(client, fetch_limit, first_fetch, last_run)

    # add event type key to the events: activities/aggreagtes
    for event in events:
        event["event_type"] = event_type

    return events


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('proofpoint_url')

    # API Credentials
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')

    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers = {
       "accept": "application/json",
       "Content-Type":"application/json"
    }

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
            payload = {
                "sort": [
                    {
                        "event.observedAt": {
                            "order": "desc",
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
                            "$dtRelativeGE": {
                                "event.observedAt": -86400000
                            }
                        }
                    ]
                }
            }
            url_suffix = f"{PROOFPOINT_EVENTS_ENDPOINT}?offset=0&limit=1&includes=screenshots&sources=cloud:isolation,email:pps,endpoint:agent,platform:analytics&trackTotalHits=false"

            events = client.test_module(url_suffix, payload)
            if events and events.get("_status", {}).get("status") in [200, 201]:
                return_results('ok')


        elif command == 'fetch-events':
            next_run = {}
            last_run = demisto.getLastRun()


            if not last_run:
                activities_last_run = {}
                aggregates_last_run = {}
            else:
                activities_last_run = last_run.get('activities', {})
                aggregates_last_run = last_run.get('aggregates', {})

            activities_data = fetch_events(client, 'activities', fetch_limit, first_fetch, activities_last_run)
            aggregates_data = fetch_events(client, 'aggregates', fetch_limit, first_fetch, aggregates_last_run)

            if activities_data:
                send_data_to_xsiam(activities_data, vendor=VENDOR, product=PRODUCT, data_type="assets")
                next_run['activities'] = get_last_run(activities_data)

            if aggregates_data:
                send_data_to_xsiam(aggregates_data, vendor=VENDOR, product=PRODUCT, data_type="assets")
                next_run['aggregates'] = get_last_run(aggregates_data)


            # check if both activities and aggregates exists in next run
            # else set last run as next run
            if "activities" not in next_run:
                next_run['activities'] = last_run.get('activities')
            if 'aggregates' not in next_run:
                next_run['aggregates'] = last_run.get('aggregates')
            demisto.updateModuleHealth({"eventsPulled": (len(activities_data) or 0) + (len(aggregates_data) or 0)})
            demisto.setLastRun(next_run)


    except Exception as e:
        err_msg = f"Error in {get_integration_name()} Integration [{e}]"
        return_error(err_msg, error=e)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

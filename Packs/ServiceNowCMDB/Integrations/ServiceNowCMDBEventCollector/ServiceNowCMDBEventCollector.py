from datetime import datetime, timedelta, timezone
import urllib3
import json
import requests
import dateparser
from typing import Any
import traceback


urllib3.disable_warnings()

VENDOR = "ServiceNow"
# PRODUCT = "CMDB"


class Client(BaseClient):
    def __init__(self, base_url, username, password, headers, verify=False, proxy=False):
        super().__init__(
            base_url=base_url,
            headers=headers,
            auth=(username, password),
            verify=verify,
            proxy=proxy
        )


    def snow_get_table_data(self, table, params, payload):
        response = self._http_request(
            'GET',
            f'/api/now/table/{table}',
            params=params,
            json_data=payload,
            resp_type="response"
        )

        if response.status_code == 200:
            response = response.json()
            events = response.get("result", [])
            return events
        else:
            return []

    def test_module(self, params):
        response = self._http_request(
            'GET',
            '/api/now/table/sys_user',
            params=params,
            ok_codes=[200]
        )
        return response


def convert_timestamp_to_dt(timestamp_str):
    """
    Convert timestamp string to datetime format
    """
    dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    return dt


def get_last_run(data: list[dict]) -> dict:
    """
    Get the info from the last run, it returns the time to query from and the last fetched incident ids
    """
    if not data:
        return {'sys_created_on': '', 'event_ids': []}
    latest_ts = data[-1]['sys_created_on']
    event_ids = [data_item['sys_id'] for data_item in data if
                    data_item['sys_created_on'] == latest_ts
                ]

    next_run = {
        'sys_created_on': latest_ts,
        'event_ids': event_ids
    }
    return next_run


def deduplicate_events(data, events_ids, fetch_time):
    """
    Remove duplicate events from the latest fetched events based on sys_id and sys_created_on
    value of last fetch.
    """
    updated_data = [data_item for data_item in data if
                        data_item['sys_id'] not in events_ids and
                        convert_timestamp_to_dt(data_item['sys_created_on']) >= convert_timestamp_to_dt(fetch_time)
                    ]
    return updated_data


def normalize_api_response(data):
    """
    Normalize api response to output data in key: value format
    """
    normalized_data = []

    for data_item in data:
        item_dict = {}
        for k,v in data_item.items():
            if isinstance(v, dict) and len(v) <= 2:
                item_dict.update({
                    k: v.get("value"),
                    f'{k}_dv': v.get("display_value")
                })
            else:
                item_dict[k] = v
        normalized_data.append(item_dict)
    return normalized_data


def fetch_create_events(client: Client, table_name: str, fetch_limit: int, first_fetch, last_run: dict[str, str]):
    """
    Fetch newly created events for a table name
    """
    if not isinstance(last_run, dict):
        last_run = {}

    last_fetch = last_run.get('sys_created_on')
    last_event_ids = last_run.get('event_ids', [])

    if not last_fetch:
        first_fetch_dt = dateparser.parse(first_fetch, settings={'RELATIVE_BASE': datetime.now(timezone.utc)})
        last_fetch = first_fetch_dt.strftime("%Y-%m-%d %H:%M:%S")

    sysparm_query = f'sys_created_on>={last_fetch}^ORDERBYsys_created_on'
    params = {
        'sysparm_display_value': "all",
        'sysparm_limit': int(fetch_limit),
        'sysparm_offset': 0,
        'sysparm_query': sysparm_query
    }
    payload = {}

    response = client.snow_get_table_data(table_name, params, payload)
    events = normalize_api_response(response)
    events = deduplicate_events(events, last_event_ids, last_fetch)
    return events


def fetch_update_events(client: Client, table_name: str, fetch_limit: int, first_fetch, last_run: dict[str, str]):
    """
    Fetch updated events for a table name
    """
    if not isinstance(last_run, dict):
        last_run = {}

    last_fetch = last_run.get('sys_updated_on')
    last_event_ids = last_run.get('event_ids', [])

    if not last_fetch:
        first_fetch_dt = dateparser.parse(first_fetch, settings={'RELATIVE_BASE': datetime.now(timezone.utc)})
        last_fetch = first_fetch_dt.strftime("%Y-%m-%d %H:%M:%S")

    sysparm_query = f'sys_updated_on>={last_fetch}^ORDERBYsys_updated_on'
    params = {
        'sysparm_display_value': "all",
        'sysparm_limit': int(fetch_limit),
        'sysparm_offset': 0,
        'sysparm_query': sysparm_query
    }
    payload = {}

    response = client.snow_get_table_data(table_name, params, payload)
    events = normalize_api_response(response)
    events = deduplicate_events(events, last_event_ids, last_fetch)
    return events


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('snow_url')

    # API Credentials
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    table = params.get('table')

    headers = {
       "accept": "application/json",
       "Content-Type":"application/json"
    }

    client = Client(
        base_url=base_url,
        username=username,
        password=password,
        headers=headers,
        verify=use_ssl,
        proxy=proxy
    )


    command = demisto.command()
    try:
        fetch_limit = params.get("eventFetchLimit", 100)
        first_fetch = params.get("eventFirstFetch", "1 days")

        if command == 'test-module':
            params = {
                        'sysparm_display_value': "all",
                        'sysparm_limit': 1,
                        'sysparm_offset': 0
                    }

            response = client.test_module(params)
            if response:
                return_results('ok')


        elif command == 'fetch-events':
            next_run = {"sys_created": {}, "sys_updated": {}}
            last_run = demisto.getLastRun() or {}

            total_events_fetched = 0
            for table_name in table:
                # fetch the created events
                last_run_created = last_run.get("sys_created", {})
                created_events = fetch_create_events(client, table_name, fetch_limit, first_fetch, last_run_created.get(table_name, {}))

                if created_events:
                    total_events_fetched += len(created_events)
                    send_events_to_xsiam(created_events, vendor=VENDOR, product=f'{table_name}')
                    next_run["sys_created"][table_name] = get_last_run(created_events)
                else:
                    next_run["sys_created"][table_name] = last_run_created.get(table_name)
                
                # fetch the updated events
                last_run_updated = last_run.get("sys_updated", {})
                updated_events = fetch_update_events(client, table_name, fetch_limit, first_fetch, last_run_updated.get(table_name, {}))

                if updated_events:
                    total_events_fetched += len(created_events)
                    send_events_to_xsiam(updated_events, vendor=VENDOR, product=f'{table_name}')
                    next_run["sys_updated"][table_name] = get_last_run(updated_events)
                else:
                    next_run["sys_updated"][table_name] = last_run_updated.get(table_name)


            # check if data exist in next run for the tables
            # else set last run as next run
            if not next_run:
                next_run = last_run

            demisto.updateModuleHealth({"eventsPulled": total_events_fetched})
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f"{str(e)}. Traceback: {traceback.format_exc()}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
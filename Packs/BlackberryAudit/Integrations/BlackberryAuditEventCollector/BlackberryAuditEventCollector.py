import demistomock as demisto
from datetime import datetime, timedelta, timezone
import urllib3
import dateparser
from typing import Any, Optional
import copy
import base64
import time
import urllib.parse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import traceback


urllib3.disable_warnings()


class AuthTokenManager():
    def __init__(self, user_id, private_key, provider):
        self.private_key = private_key
        self.user_id = user_id
        self.provider = provider
        # buffer time in seconds to be reduced from expiry time of token validity
        self.expiry_buffer = 15
        # seconds to increment in current time to format the expiry time of token
        self.expire_in_seconds = 3600

    def generate_auth_token(self):
        """
        """
        key = self.private_key.replace("\\n", "\n").encode("utf-8")

        private_key = serialization.load_pem_private_key(
            key,
            password=None
        )

        expires = int(time.time()) + self.expire_in_seconds
        data = f"expires={str(expires)}" + f"&issuer={urllib.parse.quote_plus(self.provider)}" + f"&user={urllib.parse.quote_plus(self.user_id)}" + "&"

        signature = private_key.sign(
            data.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signed = base64.b64encode(signature).decode("utf-8")
        auth_token = f"Bearer {data}:{signed}"
        return auth_token, expires

    def is_token_valid(self, token, expiry_time):
        """
        """
        if not token:
            return False
        if not expiry_time:
            return False

        current_time = int(time.time())
        if current_time >= expiry_time:
            return False

        return True

    def get_auth_token(self):
        """
        """
        context = get_integration_context()
        token = context.get("token")
        expiry_time = context.get("expires_at")

        if self.is_token_valid(token, expiry_time):
            return token
        else:
            token, expires_at = self.generate_auth_token()


            # update integration context with the new token and expiry time
            set_integration_context({
                "token": token,
                "expires_at": expires_at - self.expiry_buffer
            })
            return token


class Client(BaseClient):
    """
    Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url, user_id, private_key, provider, headers, verify=False, proxy=False):
        self.headers = headers
        self.token_manager = AuthTokenManager(user_id, private_key, provider)

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy
        )

    def get_uuids(self, payload):
        updated_headers = {**self.headers, "Authorization": self.token_manager.get_auth_token()}
        response = self._http_request(
            'GET',
            '/rooms',
            headers=updated_headers,
            json_data=payload,
            resp_type="json",
            ok_codes=[200]
        )
        return response

    def get_uuid_grouplog(self, uuid, payload):
        updated_headers = {**self.headers, "Authorization": self.token_manager.get_auth_token()}
        response = self._http_request(
            'POST',
            f'/rooms/{uuid}/grouplog/create',
            headers=updated_headers,
            json_data=payload,
            resp_type="json",
            ok_codes=[200]
        )
        return response

    def get_organisation_grouplog(self, payload):
        updated_headers = {**self.headers, "Authorization": self.token_manager.get_auth_token()}
        response = self._http_request(
            'POST',
            f'/organizations/logs/groups/create',
            headers=updated_headers,
            json_data=payload,
            resp_type="json",
            ok_codes=[200]
        )
        return response

    def test_module(self, payload):
        updated_headers = {**self.headers, "Authorization": self.token_manager.get_auth_token()}
        response = self._http_request(
            'GET',
            '/rooms',
            headers=updated_headers,
            json_data=payload,
            resp_type="response",
            ok_codes=[200]
        )
        return response


def current_utc() -> str:
    """
    Returns current UTC time in iso format
    """
    return (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")


def iso_to_milliseconds(iso_str: str) -> int:
    """
    Convert ISO formatted timestamp string to milliseconds
    """
    dt = datetime.strptime(iso_str.split("+")[0], "%Y-%m-%dT%H:%M:%S")
    return int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)


def adjust_timestamp(event_timestamp: str) -> str:
    """
    Reduce 1 minute from the event timestamp.
    """
    dt = datetime.strptime(event_timestamp, "%Y-%m-%dT%H:%M:%S")
    adjusted_dt = (dt - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")
    return adjusted_dt


def overlap_exists(events: list[dict], event_timestamp) -> bool:
    """
    Filter to check if events from previous fetch are present in new fetch or not.
    Check events based on actionDate.
    """
    return any(event.get('actionDate', '').startswith(event_timestamp) for event in events)


def deduplicate_events(events: list[dict], event_timestamp: str) -> list[dict]:
    """
    Remove duplicate events from the latest fetched events by comparing the lates events actionDate from
    last fetch
    """
    if not event_timestamp:
        return events

    last_event_ms = iso_to_milliseconds(event_timestamp)
    return [event for event in events
            if event.get("actionDate") and iso_to_milliseconds(event["actionDate"]) > last_event_ms
        ]


def should_refetch(events, event_timestamp, page_number=0):
    if not event_timestamp:
        return False
    if overlap_exists(events, event_timestamp):
        return False
    if page_number != 0:
        return False
    return True


def get_latest_ts(uuid_events, last_run_dt):
    """
    Returns latest timestamp in format: YYYY-MM-DDTHH:MM:SS
    Input format: YYYY-MM-DDTHH:MM:SS+0000
    """
    latest_dt = None
    for event in uuid_events:
        ts = event.get("actionDate")
        if not ts:
            continue

        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")

        if latest_dt is None or dt > latest_dt:
            latest_dt = dt

    return latest_dt.strftime("%Y-%m-%dT%H:%M:%S") if latest_dt else last_run_dt


def fetch_room_groups(
        client: Client,
        fetch_limit: int,
        first_fetch_dt: str,
        last_run: dict,
        vendor: str,
        product: str
    ):
    """
    """
    unprocessed_uuids = last_run.get("unprocessed_uuids")
    last_action_dates = last_run.get("action_dates", {})

    if not unprocessed_uuids:
        payload = {
            "workspaceTypes": ""
        }

        uuids_response = client.get_uuids(payload)
        unprocessed_uuids = [data['uuid'] for data in uuids_response.get("items", [])]

    num_uuids_processed = 0
    all_events = []
    next_run = copy.deepcopy(last_run)
    try:
        while unprocessed_uuids:
            uuid = unprocessed_uuids.pop(0)

            before_time = current_utc()
            after_time = last_action_dates.get(uuid) or first_fetch_dt
            payload = {
                "before": before_time + "+0000",
                "after": after_time + "+0000"
            }

            uuid_events = client.get_uuid_grouplog(uuid, payload)
            events = uuid_events.get("items", [])

            if events:
                if should_refetch(events, last_action_dates.get(uuid)):
                    refetch_after_time = adjust_timestamp(after_time)
                    payload["after"] = refetch_after_time + "+0000"

                    demisto.updateModuleHealth(f"No overlapping room group events with actionDate found. Refetching with grace time: {refetch_after_time}")
                    demisto.debug(f"No overlapping room group events with actionDate found. Refetching with grace time: {refetch_after_time}")

                    uuid_events = client.get_uuid_grouplog(uuid, payload)
                    events = uuid_events.get("items", [])

                    if not overlap_exists(events, last_action_dates.get(uuid)):
                        demisto.updateModuleHealth(f"Still no overlapping room group events found after refetch with time={refetch_after_time}. Possible API data loss.")
                        demisto.debug(f"Still no overlapping room group events found after refetch with time={refetch_after_time}. Possible API data loss.")

                events = deduplicate_events(events, last_action_dates.get(uuid))
                all_events.extend(events)
                last_action_dates[uuid] = get_latest_ts(events, last_action_dates.get(uuid))
                next_run = {
                    "action_dates": last_action_dates,
                    "unprocessed_uuids": unprocessed_uuids
                }
                demisto.setLastRun({"rooms": next_run})

            if len(all_events) >= fetch_limit:
                send_events_to_xsiam(all_events, vendor=vendor, product=product, should_update_health_module=True)
                all_events = []

            num_uuids_processed += 1
    except Exception as e:
        demisto.updateModuleHealth(f"Failed after processing {num_uuids_processed} UUIDs. \nError: {str(e)}\n{traceback.format_exc()}")
        demisto.debug(f"Failed after processing {num_uuids_processed}. \nError: {str(e)}\n{traceback.format_exc()}")
    finally:
        if all_events:
            send_events_to_xsiam(all_events, vendor=vendor, product=product, should_update_health_module=True)
            demisto.setLastRun({"rooms": next_run})


def fetch_organisation_groups(
        client: Client,
        fetch_limit: int,
        first_fetch_dt: str,
        last_run: dict,
        max_iterations: int,
        vendor: str,
        product: str
    ):
    """
    """
    last_action_date = last_run.get("action_date")
    last_payload = last_run.get("payload", {})

    page_number = int(last_payload.get("paginationInfo", {}).get("pageNumber", "0"))

    if last_payload:
        payload = copy.deepcopy(last_payload)
    else:
        before_time = current_utc()
        after_time = last_action_date or first_fetch_dt

        payload = {
            "before": before_time + "+0000",
            "after": after_time + "+0000",
            "paginationInfo": {
                "pageSize": str(fetch_limit),
                "pageNumber": str(page_number)
            }
        }

    loop_iterations = 0
    next_run = copy.deepcopy(last_run)

    while True:
        response = client.get_organisation_grouplog(payload)
        events = response.get("items", [])

        if events:
            if should_refetch(events, last_action_date, page_number):
                refetch_after_time = adjust_timestamp(after_time)
                payload["after"] = refetch_after_time + "+0000"

                demisto.updateModuleHealth(f"No overlapping organisation group log events with actionDate found. Refetching with grace time: {refetch_after_time}")
                demisto.debug(f"No overlapping organisation group log events with actionDate found. Refetching with grace time: {refetch_after_time}")

                response = client.get_organisation_grouplog(payload)
                events = response.get("items", [])

                if not overlap_exists(events, last_action_date):
                    demisto.updateModuleHealth(f"Still no overlapping organisation group log events found after refetch with time={refetch_after_time}. Possible API data loss.")
                    demisto.debug(f"Still no overlapping organisation group log events found after refetch with time={refetch_after_time}. Possible API data loss.")

            events = deduplicate_events(events, last_action_date)

            latest_action_date = get_latest_ts(events, last_action_date)
            send_events_to_xsiam(events, vendor=vendor, product=product, should_update_health_module=True)

            page_number += 1
            payload['paginationInfo']['pageNumber'] = str(page_number)
            next_run = {
                "action_date": latest_action_date,
                "payload": payload
            }
            demisto.setLastRun({"organisation": next_run})
        else:
            next_run['payload'] = {}
            demisto.setLastRun({"organisation": next_run})
            break

        if loop_iterations >= max_iterations:
            break

        loop_iterations += 1


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('blackberry_url')
    full_url = urljoin(base_url, '/api/3.0/')

    # API Credentials
    user_id = params.get('credentials', {}).get('identifier')
    private_key = params.get('credentials', {}).get('password')
    provider = params.get('provider')
    events_type = params.get('events_type')
    max_iterations = arg_to_number(params.get('max_iterations', 10))

    # Vendor and Product names
    vendor = "Blackberry"
    product = f"Audit_{events_type}"

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
        base_url=full_url,
        user_id=user_id,
        private_key=private_key,
        provider=provider,
        headers=headers,
        verify=use_ssl,
        proxy=proxy
    )


    command = demisto.command()
    try:
        fetch_limit = arg_to_number(params.get("eventFetchLimit", "500"))
        first_fetch = params.get("eventFirstFetch", "90 days")

        if command == 'test-module':
            payload = {
                "workspaceTypes": ""
            }
            response = client.test_module(payload)
            if response.status_code == 200:
                return_results('ok')
            else:
                raise DemistoException(f"Authorization failed. Pleaese re-check the credentials. \nStatus code: {response.status_code} \nReason: {response.reason}")

        elif command == 'fetch-events':
            '''
            Command to be called on each interval as defined in integration instance
            for fetching data and pushing to XSIAM dataset
            '''
            last_run = demisto.getLastRun()
            first_fetch = dateparser.parse(first_fetch, settings={'RELATIVE_BASE': datetime.now(timezone.utc)})
            first_fetch_dt = first_fetch.strftime("%Y-%m-%dT%H:%M:%S")

            if events_type == "Rooms":
                last_run_data = last_run.get("rooms", {})
                fetch_room_groups(client, fetch_limit, first_fetch_dt, last_run_data, vendor, product)
            elif events_type == "Organisation":
                last_run_data = last_run.get("organisation", {})
                fetch_organisation_groups(client, fetch_limit, first_fetch_dt, last_run_data, max_iterations, vendor, product)
            else:
                raise ValueError(f"Invalid value: {events_type} provided for Events Type parameter. Please select a valid value from the provided options.")

    except Exception as e:
        err_msg = f"Error in {get_integration_name()} Integration [{e}]. \nError occured: {traceback.format_exc()}"
        return_error(err_msg, error=e)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
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
    """
    Class for generation and checking the validity of api token

    This class is responsible for:
    - Creating signed authentication tokens using an RSA private key
    - Validating token expiration
    - Storing and retrieving tokens from integration context to avoid token generation repeatedly
    """
    def __init__(self, user_id, private_key, provider):
        """
        Initialize AuthTokenManager with authentication configuration.
        """
        self.private_key = private_key
        self.user_id = user_id
        self.provider = provider

        # buffer time in seconds to be reduced from expiry time for token validity
        self.expiry_buffer = 15

        # seconds to increment in current time to format the expiry time of token
        self.expire_in_seconds = 3600

    def generate_auth_token(self):
        """
        Generates a new signed authentication token.

        Steps:
        1. Loads the RSA private key.
        2. Format a string containing expiry, issuer, and user.
        3. Signs the string using SHA256 + PKCS#1 v1.5.
        4. Encode the formatted stirng into base64 format.
        5. Create the final bearer token.
        """
        key = self.private_key.replace("\\n", "\n").encode("utf-8")

        # Load PEM private key object
        private_key = serialization.load_pem_private_key(
            key,
            password=None
        )

        # Calculat the token expiration timestamp
        expires = int(time.time()) + self.expire_in_seconds
        data = f"expires={str(expires)}" + f"&issuer={urllib.parse.quote_plus(self.provider)}" + f"&user={urllib.parse.quote_plus(self.user_id)}" + "&"

        # Generate cryptographic signature
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
        Validate whether the token stored in integration cotent is still 
        valid and not expired.
        """

        # check if the token exists
        if not token:
            return False

        # check if the expiry time exists
        if not expiry_time:
            return False

        current_time = int(time.time())
        # If current time has passed the expiry time 
        # means the token is invalid
        if current_time >= expiry_time:
            return False

        return True

    def get_auth_token(self):
        """
        Retrieve the token from integration context if it is present and valid
        else generate a new token.

        Logic:
        - Checks integration context if token is present and valid.
        - If valid, then returns the token.
        - If missing or expired, then generate a new token and update the integration context.
        """
        # Retrieve the stored data from integration context
        context = get_integration_context()
        token = context.get("token")
        expiry_time = context.get("expires_at")

        # Reuse token if not expired
        if self.is_token_valid(token, expiry_time):
            return token
        
        # generate a new token
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
        """
        Fetch list of room UUIDs.
        """
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
        """
        Get group log for a specific room UUID.
        """
        updated_headers = {**self.headers, "Authorization": self.token_manager.get_auth_token()}

        try:
            response = self._http_request(
                'POST',
                f'/rooms/{uuid}/grouplog/create',
                headers=updated_headers,
                json_data=payload,
                resp_type="json",
                ok_codes=[200]
            )
        except Exception as e:
            raise DemistoException(f"Error: {str(e)}. Payload: {payload}. UUID: {uuid}")
        return response

    def get_organisation_grouplog(self, payload):
        """
        Create organization-level group log.
        """
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
        """
        Connectivity test method to be called when test button is clicked.
        """
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

    This function returns the current UTC time minus one minute for safety buffer when fetching the 
    records based on time filters.
    """
    return (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")


def iso_to_milliseconds(iso_str: str) -> int:
    """
    Convert ISO formatted timestamp string to milliseconds.

    The input string is in the format YYYY-MM-DDTHH:MM:SS+00:00,
    this function will split the time string on + and extract the date time only
    excluding the time offset.
    """
    dt = datetime.strptime(iso_str.split("+")[0], "%Y-%m-%dT%H:%M:%S")

    # multiplication factor to convert seconds to miliseconds.
    miliseconds_factor = 1000
    return int(dt.replace(tzinfo=timezone.utc).timestamp() * miliseconds_factor)


def adjust_timestamp(event_timestamp: str) -> str:
    """
    Subtract one minute from a timestamp string.

    This function is used when duplicate records are not found and a small backward offset
    is required to fetch the previous duplicate events.
    """

    # Parse input timestamp into datetime object
    dt = datetime.strptime(event_timestamp, "%Y-%m-%dT%H:%M:%S")

    # Apply backward offset buffer
    adjusted_dt = (dt - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")
    return adjusted_dt


def overlap_exists(events: list[dict], last_event_timestamp) -> bool:
    """
    Function to determine whether any events from a new fetch overlap with the last
    processed event timestamp.
    """

    # Return False for the following cases, means no overlap exists
    # 1. When no events are fetched in current iteration
    # 2. last_event_timestamp is empty/None, which could happen when it is the first fetch.
    if not events or not last_event_timestamp:
        return False

    # convet last event timestmap to millisenconds for conversion
    last_event_ms = iso_to_milliseconds(last_event_timestamp)
    
    # Iterate over all the events and compare if the actionDate of any event is 
    # less than or equal to the last event timestamp then return true (overlap exists)
    # else return false (no overlap exists)
    for event in events:
        action_date = event.get("actionDate")
        if not action_date:
            continue  # skip events where actionData is not present
        
        # convert current event actionDate to milliseconds for comparison
        event_dt_ms = iso_to_milliseconds(action_date)


        # Overlap condition: event already processed or same timestamp
        if event_dt_ms <= last_event_ms:
            return True

    return False


def deduplicate_events(events: list[dict], event_timestamp: str) -> list[dict]:
    """
    Remove duplicate events from the latest fetched events by comparing the latest events actionDate from
    last fetch
    """
    if not event_timestamp:
        return events

    last_event_ms = iso_to_milliseconds(event_timestamp)

    # New array to store the updated events after filtering out the 
    # duplicate events
    updated_events = []

    for event in events:
        action_date = event.get("actionDate")
        
        if not action_date:
            updated_events.append(event)
            continue

        # Convert event actionDate timestamp to milliseconds
        event_time_ms = iso_to_milliseconds(action_date)
        # Keep the new events
        if event_time_ms > last_event_ms:
            updated_events.append(event)

    return updated_events


def should_refetch(events, event_timestamp, page_number=0):
    """
    Funtion to determine whether another fetch request should be made.

    Refetch should occur only when:
        1. A previous timestamp exists (not first-ever run).
        2. No overlap is detected between fetched events and last processed event.
        3. This is the first page request.
    
    Returns:
        True: Refetch the events with adjusted timestamp
        False: No refetch is required
    """
    if not event_timestamp:
        return False
    if overlap_exists(events, event_timestamp):
        return False
    if page_number != 0:
        return False
    return True


def get_latest_ts(uuid_events, last_run_dt):
    """
    This functions extracts the recent event timestamp from the events.

    This function scans event records, identifies the latest actionDate,
    and returns it in normalized ISO format.
    """
    latest_dt = None
    for event in uuid_events:
        ts = event.get("actionDate")
        if not ts:
            continue
        
        # convert the event timestmap to datetime object
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S%z")

        if latest_dt is None or dt > latest_dt:
            latest_dt = dt

    # Return latest found timestamp or fallback to last run time
    return latest_dt.strftime("%Y-%m-%dT%H:%M:%S") if latest_dt else last_run_dt


def fetch_room_groups(
        client: Client,
        first_fetch_dt: str,
        last_run: dict,
        vendor: str,
        product: str
    ):
    """
    This function is call on each interval to fetch room group events for all available UUIDs and send them to XSIAM
    dataset.

    This functions ensures:
        - no duplicate events are ingested for a UUID
        - no events are missed between fetch cycles

    Workflow Overview:
        1. Retrieve UUID list from API if no unprocessed UUIDs are present in the integration context.
        2. Iterate through each UUID and fetch events.
        3. Detect overlaps with previously fetched events latest timestamp.
        4. Refetch with grace period if overlap not detected for any UUID.
        5. Deduplicate events based on actionDate.
        6. Send events in to XSIAM dataset.
        7. Persist updated state (latest timestamp) for each UUID in the integration context.
    """

    # Retrieve the UUIDs from context, which were not processed in the last iteration (if any)
    unprocessed_uuids = last_run.get("unprocessed_uuids", [])

    # Retrieve the latest actionDate timestamp for each UUID
    last_action_dates = last_run.get("action_dates", {})

    # Fetch the UUIDs list from Blackberry in following cases:
    # 1. It is the first integration fetch cycle
    # 2. The latest events have been fetched for each UUIDs and added to XSIAM dataset
    if not unprocessed_uuids:
        payload = {
            "workspaceTypes": ""
        }

        uuids_response = client.get_uuids(payload)

        # iterate over all the UUIDs response and extract 
        # store the uuids in to unporcessed array for fetching the events
        # if uuid is present
        unprocessed_uuids = []
        for data in uuids_response.get("items", []):
            if "uuid" in data:
                unprocessed_uuids.append(data['uuid'])
    
    # Variable to track the number of UUIDs processed
    num_uuids_processed = 0

    # List to accumulate the events for each UUID
    all_events = []

    # Iterate over each UUID sequentially and fetch events
    while unprocessed_uuids:
        uuid = unprocessed_uuids.pop(0)

        # Time window for the api query for fetching the events
        # If is the first fetch then use the first_fetch_dt as configured in integration instance
        # else use the most recent timestamp for the UUID from last fetch
        before_time = current_utc()
        after_time = last_action_dates.get(uuid) or first_fetch_dt
        payload = {
            "before": before_time + "+0000",
            "after": after_time + "+0000"
        }
        
        # Initialize the events list
        events = []

        # Fetch events for a UUID,
        # in case of failure log the error and continue the loop to process the pending unprocessed UUIDs.
        try:
            # fetch the events for a UUID
            uuid_events = client.get_uuid_grouplog(uuid, payload)
            events = uuid_events.get("items", [])
        except Exception as e:
            demisto.updateModuleHealth(f"Failed to fetch events for the UUID: {uuid}. Payload: {payload}. Processed UUID count: {num_uuids_processed} UUIDs. \nError: {str(e)}\n{traceback.format_exc()}")
            demisto.debug(f"Failed to fetch events for the UUID: {uuid}. Processed UUID count: {num_uuids_processed} UUIDs. \nError: {str(e)}\n{traceback.format_exc()}")
            
            # persist progress in context even on failure
            last_run = {
                "action_dates": last_action_dates,
                "unprocessed_uuids": unprocessed_uuids
            }
            demisto.setLastRun({"rooms": last_run})
            
            continue

        if events:
            # Check if refetch is required by using the adjusted timestamp
            # Refetch will be done in following cases:
            # 1. A previous timestamp exists (not first-ever run).
            # 2. No overlap is detected between fetched events and last processed event.
            if should_refetch(events, last_action_dates.get(uuid)):
                # Reduce 1 minute from the "after" timestamp to intentionally overlap results.
                # This guarantees no event gaps due to API latency or timestamp precision.
                refetch_after_time = adjust_timestamp(after_time)
                payload["after"] = refetch_after_time + "+0000"

                demisto.updateModuleHealth(f"No overlapping room group events with actionDate found. Refetching with grace time: {refetch_after_time}")
                demisto.debug(f"No overlapping room group events with actionDate found. Refetching with grace time: {refetch_after_time}")

                # re-fetch the events for a UUID using the adjusted timestamp
                try:
                    uuid_events = client.get_uuid_grouplog(uuid, payload)
                    events = uuid_events.get("items", [])
                except Exception as e:
                    demisto.updateModuleHealth(f"Failed to re-fetch events for the UUID: {uuid}. Payload: {payload}. Fetched events for: {num_uuids_processed} UUIDs. \nError: {str(e)}\n{traceback.format_exc()}")
                    demisto.debug(f"Failed to re-fetch events for the UUID: {uuid}. Fetched events for: {num_uuids_processed} UUIDs. \nError: {str(e)}\n{traceback.format_exc()}")
                    
                    # persist progress in context even on failure
                    last_run = {
                        "action_dates": last_action_dates,
                        "unprocessed_uuids": unprocessed_uuids
                    }
                    demisto.setLastRun({"rooms": last_run})
                    
                    continue

                # Check if overlap exists between the refetched events.
                # If still no overlap is found, possible error in the API.
                if not overlap_exists(events, last_action_dates.get(uuid)):
                    demisto.updateModuleHealth(f"Still no overlapping room group events found after refetch with time={refetch_after_time}. Possible API data loss.")
                    demisto.debug(f"Still no overlapping room group events found after refetch with time={refetch_after_time}. Possible API data loss.")

            # remove duplicate from the currently fetched events using the actionDate and last fetch timestamp
            events = deduplicate_events(events, last_action_dates.get(uuid))

            # Check if events are present after performing dedup
            # If present add the events to XSIAM dataset.
            if events:
                try:
                    # Get the most recents event timestamp for the UUID
                    # update the last_run object and the integration context with the updated data
                    last_action_dates[uuid] = get_latest_ts(events, last_action_dates.get(uuid))
                    last_run = {
                        "action_dates": last_action_dates,
                        "unprocessed_uuids": unprocessed_uuids
                    }

                    send_events_to_xsiam(events, vendor=vendor, product=product, should_update_health_module=True)

                    # Update the integration context with upated data
                    demisto.setLastRun({"rooms": last_run})
                except Exception as e:
                    demisto.updateModuleHealth(f"Failed to add events to dataset: {vendor}_{product}_raw for the UUID: {uuid}. \nError: {str(e)}\n{traceback.format_exc()}")
                    demisto.debug(f"Failed to add events to dataset: {vendor}_{product}_raw for the UUID: {uuid}. \nError: {str(e)}\n{traceback.format_exc()}")
                    
                    # persist progress in context even on failure
                    last_run = {
                        "action_dates": last_action_dates,
                        "unprocessed_uuids": unprocessed_uuids
                    }
                    demisto.setLastRun({"rooms": last_run})

                    continue
            

        # increment 1 in the number of uuids processed for fetch operations
        num_uuids_processed += 1


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
    Fetch organisation-level group log events from the API and send them to XSIAM.

    This function:
        - ensures no duplicate events are ingested for the organization group
        - ensures no events are missed between fetch cycles
        - retrieves paginated organisation events
    """

    # Most recent event timestamp from previous fetch cycle
    # Null if it is the first integration fetch cycle
    last_action_date = last_run.get("action_date")

    # Last request payload used for pagination continuattion
    # Empty dict 
    # 1. if it is the first integraiton fetch
    # 2. all the events were fetched in last fetch cycle
    last_payload = last_run.get("payload", {})

    # Extract the page number from saved payload in integration contetxt
    # Defaults to 0 if payload is empty.
    page_number = int(last_payload.get("paginationInfo", {}).get("pageNumber", "0"))

    # Check if payload exists in the integration context, 
    # resume pagination from last saved state else create new payload object
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

    # Variable to tract the number of pagination loops executed
    loop_iterations = 0
    next_run = copy.deepcopy(last_run)

    # Loop through paginated results, till any of the following condition is not met
    # 1. API returns no events
    # 2. max_iterations limit is reached (safety guard)
    while True:
        # Fetch a the organization events
        response = client.get_organisation_grouplog(payload)
        events = response.get("items", [])

        if events:
            # Check if refetch is required by using the adjusted timestamp
            # Refetch will be done in following cases:
            # 1. A previous timestamp exists (not first-ever run).
            # 2. No overlap is detected between fetched events and last processed event.
            # 3. This is the first page request.
            if should_refetch(events, last_action_date, page_number):

                # Reduce 1 minute from the "after" timestamp to intentionally overlap results.
                # This guarantees no event gaps due to API latency or timestamp precision.
                refetch_after_time = adjust_timestamp(after_time)
                payload["after"] = refetch_after_time + "+0000"

                demisto.updateModuleHealth(f"No overlapping organisation group log events with actionDate found. Refetching with grace time: {refetch_after_time}")
                demisto.debug(f"No overlapping organisation group log events with actionDate found. Refetching with grace time: {refetch_after_time}")

                # re-fetch the organization events using the adjusted timestamp
                response = client.get_organisation_grouplog(payload)
                events = response.get("items", [])

                # Check if overlap exists between the refetched events.
                # If still no overlap is found, possible error in the API.
                if not overlap_exists(events, last_action_date):
                    demisto.updateModuleHealth(f"Still no overlapping organisation group log events found after refetch with time={refetch_after_time}. Possible API data loss.")
                    demisto.debug(f"Still no overlapping organisation group log events found after refetch with time={refetch_after_time}. Possible API data loss.")

            # remove duplicate from the currently fetched events using the actionDate and last fetch timestamp
            events = deduplicate_events(events, last_action_date)
            
            # Check if events are present after performing dedup
            # If present add the events to XSIAM dataset.
            if events:
                latest_action_date = get_latest_ts(events, last_action_date)
                send_events_to_xsiam(events, vendor=vendor, product=product, should_update_health_module=True)

                # increment 1 to the pageNumber for fetching paginated records.
                page_number += 1
                payload['paginationInfo']['pageNumber'] = str(page_number)
                next_run = {
                    "action_date": latest_action_date,
                    "payload": payload
                }
                demisto.setLastRun({"organisation": next_run})
        else:
            # No events returned, then pagination finished
            # Clear payload so next run starts fresh
            next_run['payload'] = {}
            demisto.setLastRun({"organisation": next_run})
            break
        
        # stop the loop if number of max_iteration exceeds the loop execution
        if loop_iterations >= max_iterations:
            break
        
        # increment the number of loop iterations
        loop_iterations += 1
    demisto.updateModuleHealth("")
    

def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('blackberry_url')
    # full_url = urljoin(base_url, '/api/3.0/')
    full_url = base_url.rstrip("/") + "/api/3.0"

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

            # Fetch the events based on the 'Events Type' as set in the integration instance.
            # If it is set to Rooms:
            # 1. Excecute the function fetch_room_group(...) which first fetches all the room UUIDs.
            # 2. And then fetch the eevents for each room UUID.
        
            # If it is set to Organization:
            # 1. Execute the funciton fetch_organization_groups(...)
            # 2. 
            if events_type == "Rooms":
                last_run_data = last_run.get("rooms", {})
                fetch_room_groups(client, first_fetch_dt, last_run_data, vendor, product)
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
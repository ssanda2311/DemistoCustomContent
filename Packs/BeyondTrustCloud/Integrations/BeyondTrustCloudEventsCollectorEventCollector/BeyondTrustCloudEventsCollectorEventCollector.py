from datetime import datetime, timedelta, timezone
import urllib3
import dateparser
import xml.etree.ElementTree as ET
import re
import base64
import demistomock as demisto
from CommonServerPython import *
import xmltodict


urllib3.disable_warnings()


class AuthClient(BaseClient):
    """
    Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """
    def __init__(self, base_url, client_id, client_secret, verify=False, proxy=False):
        """
        Initialize authentication client.
        """

        # Store credentials for token generation
        self.client_id = client_id
        self.client_secret = client_secret

        # Initialize BaseClient for HTTP handling
        super().__init__(
            base_url,
            verify=verify,
            proxy=proxy
        )

    def generate_auth_token(self):
        """
        Generate a new OAuth access token using client credentials grant.

        Flow:
        1. Encode client_id and client_secret as Base64.
        2. Send POST request to /oauth2/token.
        3. Return the token response.
        """

        # Combine client_id and client_secret in required format
        auth_str = f'{self.client_id}:{self.client_secret}'.encode()

        # Prepare headers with Basic authentication
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(auth_str).decode(),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        # OAuth payload for client credentials flow
        auth_payload = {
            "grant_type": "client_credentials"
        }

        response = self._http_request(
            'POST',
            f'/oauth2/token',
            headers=headers,
            data=auth_payload,
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

    def __init__(self, base_url, client_id, client_secret, verify=False, proxy=False):
        """
        Initialize the API client.
        """

        # Create dedicated authentication client
        # Keeps token logic separated from API logic
        self.oauth = AuthClient(base_url, client_id, client_secret, verify, proxy)

        # Initialize BaseClient for HTTP handling
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy
        )

    def get_auth_token(self):
        """
        Retrieve a valid Bearer token.

        Flow:
        1. Check integration context if token is present.
        2. If token exists and not expired, then reuse the same.
        3. If expired or missing, then generate new token.
        4. Store token and expiry time in integration context.
        """

        token_expiry_buffer_seconds = 300  # 5 minutes before token expiry
        millisecond_in_second = 1000  # multiplication factor to convert seconds to milliseconds

        # Retrieve stored token data from integration context
        context = get_integration_context()
        access_token = context.get("access_token")
        expiry_time = context.get("expiry_time", 0)

        # Current time in milliseconds
        current_time = date_to_timestamp(datetime.now())

        # Reuse token if still valid
        # Else generate a new token
        if access_token and expiry_time > current_time:
            demisto.debug("Using the access token from integration context")
            return f"Bearer {access_token}"

        demisto.debug("Access token missing or expired — generating new auth token.")

        # Request new access token
        result = self.oauth.generate_auth_token()

        '''
        Create token expiry time in miliseconds by reducing 'token_expiry_buffer_seconds' from the
        original expiry time received from auth token response and multiply by 'millisecond_in_second'
        to convert into miliseconds
        '''
        expiry_time = current_time + (result['expires_in'] - token_expiry_buffer_seconds) * millisecond_in_second

        # Store updated token details in integration context
        token_context = {
            'access_token': result.get('access_token'),
            'expiry_time': expiry_time,
        }
        set_integration_context(token_context)

        return "Bearer " + result.get('access_token')

    def get_events(self, params):
        """
        Retrieve session events from reporting API.
        """

        headers = {
            "Authorization": self.get_auth_token()
        }

        response = self._http_request(
            'POST',
            url_suffix='/api/reporting',
            headers=headers,
            params=params,
            resp_type="response",
            ok_codes=[200]
        )

        if response.status_code == 200:
            response = response.text
            return response
        else:
            return ''

    def test_module(self, params):
        """
        Used during 'test-module' command execution,
        for testing the connectivity and validating the credentials
        """
        headers = {
            "Authorization": self.get_auth_token()
        }

        response = self._http_request(
            'POST',
            url_suffix='/api/reporting',
            headers=headers,
            params=params,
            resp_type="response",
            ok_codes=[200]
        )

        if response.status_code == 200:
            return 'ok'


def current_utc_seconds() -> int:
    """
    Get the current UTC time in Unix timestamp format (seconds).
    """
    return int(datetime.now(timezone.utc).timestamp())


def iso_to_seconds(date_str: str) -> int:
    """
    Convert ISO 8601 formatted timestamp string to Unix timestamp (seconds).
    """

    # remove the timezone offset from the time string
    date_str_updated = date_str.split("+")[0]

    # convert date time string to date time object
    dt = datetime.strptime(date_str_updated, "%Y-%m-%dT%H:%M:%S")

    # return the timestamp in seconds format
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def get_max_timestamp_and_lseq(data):
    """
    This function extracts the maximum 'end_time' timestamp from fetched events
    and collect all lseq IDs associated with that timestamp.

    This ensures:
    - Correct tracking of latest fetch position.
    - Proper deduplication when multiple events share same timestamp.
    """
    max_timestamp = None
    lseq = []

    for item in data:
        event_end_time = item.get("end_time", {}).get("#text")
        # Skip events without end_time
        if not event_end_time:
            continue

        current_ts = iso_to_seconds(event_end_time)
        current_lseq = item.get("lseq")

        # First valid timestamp encountered
        if max_timestamp is None:
            max_timestamp = current_ts
            lseq = [current_lseq]
            continue

        # If timestamp is greater, replace max_timestmap and lseq
        if current_ts > max_timestamp:
            max_timestamp = current_ts
            lseq = [current_lseq]

        # If timestamp is same, append the current lseq
        elif current_ts == max_timestamp:
            lseq.append(current_lseq)

    # Filter None values from the lseq
    lseq = [lseq_id for lseq_id in lseq if lseq_id]

    return max_timestamp, lseq


def deduplicate_events(data: list[dict], prev_lseq: list[str], prev_ts: int) -> list[dict]:
    """
    Remove duplicate events during incremental fetch.

    An event is considered new if:
    - Its timestamp is greater than the previous maximum timestamp, OR
    - Its timestamp equals the previous maximum timestamp AND
      its lseq was not previously processed.
    """

    updated_data = []

    for item in data:
        # extract the end timestamp from the session event data
        event_end_time = item.get("end_time", {}).get("#text")

        # If event has no timestamp, include it by default
        if not event_end_time:
            updated_data.append(item)
            continue

        current_lseq = item.get('lseq')
        event_ts = iso_to_seconds(event_end_time)

        # Include event if:
        # 1. Current lseq_id is not present for the max timestmap identified in the last fetch cycle
        # 2. Current event 'end_time' is greater then the previous max timestamp
        if current_lseq not in prev_lseq and event_ts >= prev_ts:
            updated_data.append(item)

    return updated_data

def should_refetch_events(data: list[dict], prev_lseq: list):
    """
    Determine whether events should be refetched using a reduced timestamp window.

    This function is used in incremental fetching logic to handle edge cases
    where no overlap is detected between previously processed events (based
    on lseq ids) and newly fetched events.

    Refetch is NOT required if:
    - No new data was returned
    - No previous lseq values exist (first fetch scenario)
    - An overlap exists between previous and current lseq values
    """

    # If no new events were returned, no need to refetch
    if not data:
        return False

    # If there is no previous state (initial fetch), no refetch is required
    if not prev_lseq:
        return False

    # If overlap exists between old and new lseq values,
    # incremental fetch worked correctly — no need to refetch
    if overlap_exists(data, prev_lseq):
        return False

    return True


def overlap_exists(data: list[dict], prev_lseq: list[str]) -> bool:
    """
    Check whether there is any overlap between previously fetched data by comparing
    lseq ids from current fetch and lseq ids found in last fetch cycle for the
    maximum 'end_time'
    """

    # Extract lseq values from newly fetched events
    # excluding the null or empty values
    current_lseq_ids = [data_item.get('lseq') for data_item in data if data_item.get('lseq')]

    # Return True if any previously stored lseq exists in current results
    return any(lseq_id in prev_lseq for lseq_id in current_lseq_ids)


def get_next_run(data: list[dict]) -> dict:
    """
    Build the next_run object for incremental fetching.

    This function:
    - Identifies the maximum timestamp from the current batch
    - Collects all lseq values associated with that timestamp
    - Returns them in a structured dictionary to be stored as last_run
    """

    # Determine latest timestamp and corresponding lseq values
    latest_ts, lseq_id = get_max_timestamp_and_lseq(data)

    # Crate dict object for next_run to store in integration context
    next_run = {
        'end_time': latest_ts,
        'lseq_id': lseq_id
    }

    return next_run


def convert_xml_to_dict(xml_text: str, vendor, product) -> list:
    """
    Convert XML data to python dict format.
    Ensure that the session object is always of type list.

    This function returns the session_events if conversion from xml to json successful.
    If conversion is not successful then pushes the raw xml data to the dataset,
    and also logs an error for the conversion failure.
    """
    # If the xml text is blank then return empty list
    if not xml_text:
        return []
    
    # If xml text if present, then convert xml to json
    # If conversion is success: then return session_events
    # Else push raw xml to xsiam dataset under _raw_log field
    try:
        data = xmltodict.parse(xml_text, force_list=("session",))
        sessions = data.get("session_list", {}).get("session", [])
        return sessions
    except Exception as e:
        # Format the data to be pyushed into dataset
        data =  {
            "_raw_log": xml_text,
            "error": "Error: Failed to convert xml to json"
        }

        # Push the raw xml data into dataset
        send_events_to_xsiam([data], vendor=vendor, product=product, should_update_health_module=True)

        demisto.debug(f"XML parsing failed: {str(e)}")
        demisto.updateModuleHealth(f"XML parsing failed: {str(e)}")

        # Return empty list
        return []


def fetch_events(client: Client, first_fetch: int, last_run: dict, vendor: str, product: str) -> list:
    """
    Fetch events incrementally from the BeyondTrust Reporting API.

    This function:
    - Determines the correct timestamp to query from (first fetch or last_run)
    - Fetches session data from the API
    - Parses XML and extracts events into json format
    - Validates overlap with previously fetched events
    - Performs a refetch with a grace period if overlap is not detected
    - Deduplicates events
    - Sends new events to XSIAM
    - Updates last_run for the next fetch cycle
    """
    # Retrieve last stored timestamp and sequence IDs
    last_fetch = last_run.get('end_time', None)
    last_lseq_id = last_run.get('lseq_id', [])

    # Grace period (sec) to refetch earlier events when overlap is not detected
    refetch_grace_period_seconds = 10

    # Determine the starting timestamp for the current fetch cycle
    # Use first_fetch for initial run, otherwise continue from last_fetch
    if not last_fetch:
        end_time = first_fetch
    else:
        end_time = last_fetch

    # Query parameters definition for the BeyondTrust API
    """
    Link for the API documentation: https://docs.beyondtrust.com/rs/reference/reporting-api#supportsessionlisting

    start_date=[YYYY-MM-DD]
        Specifies that the report should return all sessions, even those still in progress,
        that began on or after this date and that are within the duration specified below.

    start_time=[timestamp]
        Specifies that the report should return all sessions,
        even those still in progress, that began at or after this time and
        that are within the duration specified below. The time must be a UNIX timestamp (UTC).

    end_date=[YYYY-MM-DD]
        Specifies that the report should return only closed sessions that ended on or
        after this date and that are within the duration specified below.

    end_time=[timestamp]
        Specifies that the report should return only closed sessions that ended at or
        after this time and that are within the duration specified below. The time must be a UNIX timestamp (UTC).

    duration=[integer]
        Length of time from the specified date or time for which you wish to pull reports, or
        0 to pull from the specified date to present. If start_date or end_date is specified, duration will represent days;
        if start_time or end_time is specified, duration will represent seconds.
    """

    events_params = {
        'end_time': end_time,
        'duration': 0,
        'generate_report': 'SupportSession',
    }

    # Fetch raw session data from API
    response = client.get_events(events_params)

    # Parse XML response
    session_events = convert_xml_to_dict(response, vendor, product)

    # Check if the events needs to refetched using the reduced timestamp
    # Refetch is NOT required if:
    # 1. No new data was returned
    # 2. No previous lseq values exist (initial integration run)
    # 3. An overlap exists between previous and current lseq values
    if should_refetch_events(session_events, last_lseq_id):
        refetch_time = end_time - refetch_grace_period_seconds
        events_params["end_time"] = refetch_time

        # Update end_time for dedup logic
        end_time = refetch_time

        demisto.updateModuleHealth(f"No overlapping events found. Refetching with grace time(sec): {refetch_time}")
        demisto.debug(f"No overlapping events found. Refetching with grace time(sec): {refetch_time}")

        # Refetch events using reduced timestamp
        response = client.get_events(events_params)

        # Parse XML response
        session_events = convert_xml_to_dict(response, vendor, product)

        # If overlap still not detected, log possible API data loss
        if not overlap_exists(session_events, last_lseq_id):
            demisto.updateModuleHealth(f"Still no overlapping events found after refetch with time={refetch_time}. Possible API data loss.")
            demisto.debug(f"Still no overlapping events found after refetch with time={refetch_time}. Possible API data loss.")

    # Remove duplicate events based on stored 'end_time' timestamp and lseq
    filtered_events = deduplicate_events(session_events, last_lseq_id, end_time)

    # If events are present after removing the duplicate events
    # then send the events to xsiam
    # and update the integration context
    if filtered_events:
        # Create next_run object from latest events
        next_run = get_next_run(filtered_events)
        send_events_to_xsiam(filtered_events, vendor=vendor, product=product, should_update_health_module=True)
        demisto.setLastRun(next_run)


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()

    # Vendor and Product names
    vendor = "BeyondTrust"
    product = "Cloud"

    # API Credentials
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
    hostname = params.get('hostname')

    # Base URL
    base_url = f'https://{hostname}'

    use_ssl = params.get('secure', False)
    proxy = params.get('proxy', False)

    '''
    Inititate client class object to be used for sending API calls.
    '''
    client = Client(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        verify=use_ssl,
        proxy=proxy
    )


    command = demisto.command()
    try:
        first_fetch_dt = dateparser.parse(
            params.get("eventFirstFetch", "1 days"),
            settings={'RELATIVE_BASE': datetime.now(timezone.utc)}
        )
        first_fetch = iso_to_seconds(first_fetch_dt.strftime("%Y-%m-%dT%H:%M:%S"))

        if command == 'test-module':
            params = {
                'end_time': first_fetch,
                'duration': 0,
                'generate_report': 'SupportSession',
            }
            response = client.test_module(params)
            return_results(response)

        elif command == 'fetch-events':
            '''
            Command to be called on each interval as defined in integration instance
            for fetching data and pushing to XSIAM dataset
            '''
            last_run = demisto.getLastRun()
            fetch_events(client, first_fetch, last_run, vendor, product)

    except Exception as e:
        err_msg = f"Error in {get_integration_name()} Integration [{e}]"
        return_error(err_msg, error=e)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
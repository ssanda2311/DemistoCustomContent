from datetime import datetime, timedelta, timezone
import urllib3
import dateparser
import xml.etree.ElementTree as ET
import re
import base64
import demistomock as demisto
from CommonServerPython import *


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
            response = response.content
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


class SessionParser():
    """
    This class is responsible for parsing BeyondTrust Support Session XML responses
    into structured Python dictionaries suitable for XSIAM ingestion.

    Responsibilities:
    - Extract top-level session metadata.
    - Parse nested structures (rep_list, customer_list, team_list).
    - Recursively convert XML session_details into dictionary format.
    - Normalize certain fields (e.g., split IP:port values).
    """

    def __init__(self, hostname, namespace):
        self.ns = namespace
        self.hostname = hostname

    def get_events(self, session: str):
        """
        convert the xml session report into discrete events
        """
        return self.__get_events_from_session(session)

    def __get_events_from_session(self, support_session: ET.Element):
        """
        Extracts structured session metadata and nested details
        from a <support_session> XML element.
        """

        events = {}

        # Basic session metadata
        events['lsid'] = support_session.get("lsid")
        events['external_key'] = self.get_text(support_session, './/xmlns:external_key')
        events['session_type'] = self.get_text(support_session, './/xmlns:session_type')
        events['lseq'] = self.get_text(support_session, './/xmlns:lseq')

        # Chat URLs
        events['session_chat_view_url'] = self.get_text(support_session, './/xmlns:session_chat_view_url')
        events['session_chat_download_url'] = self.get_text(support_session, './/xmlns:session_chat_download_url')

        # Attach device hostname for enrichment
        events['device_host'] = self.hostname

        # File operation counts
        events['file_transfer_count'] = self.get_text(support_session, './/xmlns:file_transfer_count')
        events['file_move_count'] = self.get_text(support_session, './/xmlns:file_move_count')
        events['file_delete_count'] = self.get_text(support_session, './/xmlns:file_delete_count')

        # Primary user metadata
        events['primary_customer'] = {
            'name': self.get_text(support_session, './/xmlns:primary_customer'),
            'gsnumber': self.get_attr(support_session, './/xmlns:primary_customer', 'gsnumber')
        }
        events['primary_rep'] = {
            'name': self.get_text(support_session, './/xmlns:primary_rep'),
            'gsnumber': self.get_attr(support_session, './/xmlns:primary_rep', 'gsnumber')
        }

        # Nested lists
        events['rep_list'] = self.get_nested_data(support_session.find('xmlns:rep_list', self.ns), self.ns)
        events['customer_list'] = self.get_nested_data(support_session.find('.//xmlns:customer_list', self.ns), self.ns)
        events['team_list'] = self.get_nested_data(support_session.find('.//xmlns:team_list', self.ns), self.ns)


        # Time fields
        events['end_time'] = self.get_text(support_session, './/xmlns:end_time')
        events['start_time'] = self.get_text(support_session, './/xmlns:start_time')
        events['rep_join_time'] = self.get_text(support_session, './/xmlns:rep_join_time')

        # Detailed session activity
        events['events'] = self.parse_session_details(support_session.find('xmlns:session_details', self.ns))

        return events

    def get_text(self, root, path):
        """
        Extract text from XML element.
        """
        elem = root.find(path, self.ns)
        return elem.text.strip() if elem is not None and elem.text else None


    def get_attr(self, root, path, attr):
        """
        Extract attribute from XML element.
        """
        elem = root.find(path, self.ns)
        return elem.get(attr) if elem is not None else None

    def element_to_dict(self, element: ET.Element):
        """
        Recursively convert XML element (and children) into dictionary.
        """

        # If no children element, then return text
        if not list(element):
            return (element.text or "").strip()

        result = {}

        for child in element:
            tag = child.tag.split('}', 1)[-1]
            value = self.element_to_dict(child)

            if tag in result:
                if not isinstance(result[tag], list):
                    result[tag] = [result[tag]]
                result[tag].append(value)
            else:
                result[tag] = value

        return result

    def get_nested_data(self, element: ET.Element, xmlns):
        """
        Convert list-based nested XML elements (rep_list, customer_list, etc.)
        into structured Python dictionaries.
        """

        data = []

        if element is None:
            return []

        for ele in element:
            data_item = {}

            # Include element attributes
            data_item.update(ele.attrib)

            for child in ele:
                tag = child.tag.split('}', 1)[-1]

                # Recursive handling for nested structures
                if list(child):
                    data_item[tag] = self.element_to_dict(child)
                    continue

                value = (child.text or "").strip()
                if not value:
                    continue

                # Split IP and port if format is "ip:port"
                if tag in ("public_ip", "private_ip") and ":" in value:
                    ip, port = value.split(":", 1)
                    data_item[tag] = ip
                    data_item[f"{tag}_port"] = port
                else:
                    data_item[tag] = value

            data.append(data_item)

        return data

    def parse_session_details(self, session_element: ET.Element):
        """
        Parse <session_details> block and return list of structured events.
        """

        events = []
        if session_element is None:
            return []

        for event in session_element.findall("xmlns:event", self.ns):
            events.append(self.parse_element(event))

        return events

    def parse_element(self, element: ET.Element):
        """
        Recursive XML-to-dict converter for session detail events.
        """

        node = {}

        # Add attributes
        if element.attrib:
            node.update(element.attrib)

        children = list(element)

        # No children
        if not children:
            text = (element.text or "").strip()
            if node and text:
                node["text"] = text
                return node
            return text if text else node

        for child in children:
            tag = child.tag.split('}', 1)[-1]

            # handling for key-value style nodes and convert to dict
            if tag == "value" and "name" in child.attrib:
                key = child.attrib.get("name")
                val = child.attrib.get("value")
                node[key] = val
                continue

            child_value = self.parse_element(child)

            if tag in node:
                if not isinstance(node[tag], list):
                    node[tag] = [node[tag]]
                node[tag].append(child_value)
            else:
                node[tag] = child_value

        return node


def get_xml_namespace(session_tree: ET.Element):
    # Parse the namespace from the XML data,
    # which is used for search all the data elements in the XML
    m = re.match(r'\{(.*)\}', session_tree.tag)
    return { 'xmlns': m.group(1) }


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
        # Skip events without end_time
        if "end_time" not in item:
            continue

        current_ts = iso_to_seconds(item["end_time"])
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
        event_end_time = item.get('end_time')

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
    current_lseq_ids = [data_item.get('lseq') for data_item in data]

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


def fetch_events(client: Client, hostname: str, first_fetch: int, last_run: dict, vendor: str, product: str) -> list:
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
    session_tree = ET.fromstring(response)
    xmlns = get_xml_namespace(session_tree)

    # Initialize session parser to convert XML to JSON
    sessionparser = SessionParser(hostname, xmlns)

    session_events = []
    for session in session_tree:
        session_event = sessionparser.get_events(session)
        session_events.append(session_event)

    # Check if session events are present
    if session_events:
        # Check if the events needs to refetched using the reduced timestamp
        # Refetch is NOT required if:
        # 1. No new data was returned
        # 2. No previous lseq values exist (initial integration run)
        # 3. An overlap exists between previous and current lseq values
        if should_refetch_events(session_events, last_lseq_id):
            refetch_time = end_time - refetch_grace_period_seconds
            events_params["end_time"] = refetch_time

            demisto.updateModuleHealth(f"No overlapping events found. Refetching with grace time(sec): {refetch_time}")
            demisto.debug(f"No overlapping events found. Refetching with grace time(sec): {refetch_time}")

            # Refetch events using reduced timestamp
            response = client.get_events(events_params)

            session_tree = ET.fromstring(response)
            xmlns = get_xml_namespace(session_tree)

            sessionparser = SessionParser(hostname, xmlns)

            session_events = []
            for session in session_tree:
                session_event = sessionparser.get_events(session)
                session_events.append(session_event)

            # If overlap still not detected, log possible API data loss
            if not overlap_exists(session_events, last_lseq_id):
                demisto.updateModuleHealth(f"Still no overlapping events found after refetch with time={refetch_time}. Possible API data loss.")
                demisto.debug(f"Still no overlapping events found after refetch with time={refetch_time}. Possible API data loss.")

        # Remove duplicate events based on stored 'end_time' timestamp and lseq
        filtered_events = deduplicate_events(session_events, last_lseq_id, end_time)

        # If events are present after removing the duplicate events
        # then send the evetns to xsiam
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
            fetch_events(client, hostname, first_fetch, last_run, vendor, product)

    except Exception as e:
        err_msg = f"Error in {get_integration_name()} Integration [{e}]"
        return_error(err_msg, error=e)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
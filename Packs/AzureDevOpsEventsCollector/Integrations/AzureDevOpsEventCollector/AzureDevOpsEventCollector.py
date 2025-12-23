from datetime import datetime, timedelta, timezone
import urllib3
import dateparser
import base64
from typing import Any, Optional

urllib3.disable_warnings()

class AuthClient(BaseClient):
    """
    Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """
    def __init__(self, base_url, client_id, client_secret, tenant_id, scope, verify=False, proxy=False):
        self.tenant_id = tenant_id
        self.auth_payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope
        }

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy
        )

    def generate_auth_token(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        response = self._http_request(
            'POST',
            f'/{self.tenant_id}/oauth2/v2.0/token',
            headers=headers,
            data=self.auth_payload,
            resp_type="json",
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

    def __init__(self, base_url, auth_url, client_id, client_secret, tenant_id, scope, organization, api_version, verify=False, proxy=False):
        self.organization = organization
        self.api_version = api_version
        self.oauth = AuthClient(auth_url, client_id, client_secret, tenant_id, scope, verify, proxy)

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

    def azure_devops_get_logs(self, params):
        url_suffix = f'/{self.organization}/_apis/audit/auditlog'
        params.update({
            'api-version': self.api_version
        })

        headers = {
            "Authorization": self.get_auth_token()
        }

        response = self._http_request(
            'GET',
            url_suffix,
            headers=headers,
            params=params,
            resp_type="json",
            ok_codes=[200]
        )
        return response

    def test_module(self, params={}):
        # response = self.azure_devops_get_logs({})
        # if respoonse:
        #     return "ok"
        response = self.oauth.generate_auth_token()
        if "access_token" in response:
            return "ok"
        else:
            return f"Access token is not present in the response: {response}. Please check the credentials."


def reduce_1ms(timestamp):
    """
    Reduce 1 ms from the timestamp.
    """
    # remove Z from end of timestamp
    timestamp = timestamp.rstrip("Z")

    # Split into main part and fractional part
    if "." in timestamp:
        main, frac = timestamp.split(".")
    else:
        main, frac = timestamp, ""

    # Keep the 7th digit separately
    last_digit = "0"

    if len(frac) > 6:
        last_digit = frac[6]
        frac = frac[:6]

    frac = frac.ljust(6, "0")

    timestamp_new = f"{main}.{frac}"

    dt = datetime.fromisoformat(timestamp_new).replace(tzinfo=timezone.utc)  # Parse str into datetime
    dt = dt - timedelta(milliseconds=1)   # Subtract 1 ms from datetime

    base = dt.strftime("%Y-%m-%dT%H:%M:%S")  # create the base time back from dt

    # Get microseconds (Python supports 6)
    micro = f"{dt.microsecond:06d}"

    # Reconstruct 7-digit fractional seconds (Azure format)
    frac7 = micro + last_digit

    # Return final timestamp with Z
    return f"{base}.{frac7}Z"


def get_last_run(logs: list[dict]) -> dict:
    """
    Get the info from the last run, it returns the time to query from and the last fetched incident ids
    """
    latest_ts = logs[0]["timestamp"]
    ids = [log["id"] for log in logs if log["timestamp"] == latest_ts]

    next_run = {
        'timestamp': latest_ts,
        'ids': ids
    }
    return next_run


def normalize_ts(ts: str) -> datetime:
    """
    Convert Azure DevOps timestamp with variable precision into datetime.
    """
    # remove Z from the timestamp str
    ts = ts.rstrip("Z")

    # Split seconds into main and fractional part
    if "." in ts:
        main, frac = ts.split(".")
        # pad ractional part to 6 digits for python compatible microseconds format
        frac = (frac + "000000")[:6]
        ts = f"{main}.{frac}"
    return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)


def overlap_exists(logs: list[dict], ids: list[str]) -> bool:
    """
    Filter to check if overlapping events are present or not in logs fetch last batch data
    """
    current_ids = [log["id"] for log in logs]
    return any(_id in current_ids for _id in ids)


def deduplicate_logs(logs: list[dict], ids: list[str], fetch_time: str) -> list[dict]:
    """
    Remove duplicate audit logs from the latest fetched logs by comparing id and timestamp from
    last fetch
    """
    last_dt = normalize_ts(fetch_time)
    filtered_audit_logs = []

    for log in logs:
        log_ts = log["timestamp"]
        log_dt = normalize_ts(log_ts)

        if log["id"] not in ids and log_dt >= last_dt:
            filtered_audit_logs.append(log)

    return filtered_audit_logs


def fetch_events(client: Client, fetch_limit: int, first_fetch: str, last_run: dict) -> list[dict]:
    """
    Format the payload and the fetch the API response.
    Perform deduplication of fetched response by comparing with the previous fetch (only if continuation token was not present in last fetch)
    """
    last_fetch = last_run.get('last_fetch_initial_timestamp')
    continuation_token = last_run.get("continuation_token")
    last_fetch_ids = last_run.get('last_fetch_ids', [])
    next_run = {}

    '''
    set flag to denote whether it is the batch's initial fetch
    or the continuation fetch
    '''
    batch_initial_fetch = True

    if not last_fetch:
        first_fetch_dt = dateparser.parse(first_fetch, settings={'RELATIVE_BASE': datetime.now(timezone.utc)})

        if first_fetch_dt.tzinfo is None:
            first_fetch_dt = first_fetch_dt.replace(tzinfo=timezone.utc)
        last_fetch = first_fetch_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Intitial query params
    params = {
        "batchSize": fetch_limit,
        "skipAggregation": True
    }

    '''
    If continuation token was present in last fetch,
    then use the continuation token to fetch next page
    else use the timestamp of latest event to fetch the audit logs
    '''
    if continuation_token:
        # update flag to False, when fetching continuation events
        batch_initial_fetch = False
        params.update({
            "continuationToken": continuation_token,
            "startTime": last_run["fetch_start_timestamp"]
        })
    else:
        # reduce 1 milisecond from last fetch to avoid missing logs, if it is not the first fetch
        start_time = reduce_1ms(last_fetch) if "last_fetch_initial_timestamp" in last_run else last_fetch
        params.update({
            "startTime": start_time
        })


    response = client.azure_devops_get_logs(params)

    # parse audit logs from the api response
    audit_logs = response.get("decoratedAuditLogEntries", [])

    # check forflag in api response to indentify whether more continuing events are present or not
    has_more_logs = response.get("hasMore", False)

    # set new continuation token if HasMore flag is True in api response
    new_continuation_token = response.get("continuationToken") if has_more_logs else None

    '''
    Get the first event timestamp if it is the initial fetch of a batch.
    For continuation fetch the timestamp will be received in decreasing order
    So, saving the latest timestamp in context for the next initial batch's fetch
    '''
    if batch_initial_fetch and audit_logs:
        next_fetch = audit_logs[0]["timestamp"]

        # collect the event ids for the same next_fetch timestamp
        event_ids = [log['id'] for log in audit_logs if log["timestamp"] == next_fetch]

        # Set the next_run data for updating the integration context
        next_run = {
            'last_fetch_initial_timestamp': next_fetch,
            'continuation_token': new_continuation_token,
            'last_fetch_ids': event_ids,
            'fetch_start_timestamp': start_time
        }

    # if next_run is empty then set last_run as next_run
    if not next_run:
        next_run = last_run
        next_run["continuation_token"] = new_continuation_token

    '''
    If new logs are present and also event ids are present in integration context from the last initial batch fetch
    then check for overlapping events and deduplcate the logs.
    '''
    if audit_logs and last_fetch_ids and not has_more_logs:
        # check the overlapping events
        if not overlap_exists(audit_logs, last_fetch_ids):
            demisto.updateModuleHealth(f"No overlapping logs found for the fetch in timeframe between {last_run.get('fetch_start_timestamp')} to {last_run.get('last_fetch_initial_timestamp')}. Possible API data loss.")
            demisto.debug(f"No overlapping logs found for the fetch in timeframe between {last_run.get('fetch_start_timestamp')} to {last_run.get('last_fetch_initial_timestamp')}. Possible API data loss.")

        # Audit events deduplication
        audit_logs = deduplicate_logs(audit_logs, last_fetch_ids, last_fetch)

    return audit_logs, next_run


def test_module(client: Client):
    """
    Function to be called when test button is clicked on integration instance
    """
    response = client.test_module()
    return_results(response)


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()

    base_url = params.get('base_url')
    auth_url = params.get('auth_url')

    # Vendor and Product name for dataset
    vendor = "Azure_DevOps"
    product = "Audit"

    # Get the credentials from integration parameters
    organization = params.get('organization')
    api_version = params.get('api_version')
    tenant_id = params.get('tenant_id')
    scope = params.get('scope')
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')

    use_ssl = params.get('secure', False)
    proxy = params.get('proxy', False)


    '''
    Inititate client class object to be used for sending API calls.
    '''
    client = Client(
        base_url=base_url,
        auth_url=auth_url,
        client_id=client_id,
        client_secret=client_secret,
        tenant_id=tenant_id,
        scope=scope,
        organization=organization,
        api_version=api_version,
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

            audit_logs, next_run = fetch_events(client, fetch_limit, first_fetch, last_run)

            if audit_logs:
                send_events_to_xsiam(audit_logs, vendor=vendor, product=product)

            demisto.updateModuleHealth({"eventsPulled": (len(audit_logs) or 0)})
            demisto.setLastRun(next_run)

    except Exception as e:
        err_msg = f"Error in {get_integration_name()} Integration [{e}]"
        return_error(err_msg, error=e)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
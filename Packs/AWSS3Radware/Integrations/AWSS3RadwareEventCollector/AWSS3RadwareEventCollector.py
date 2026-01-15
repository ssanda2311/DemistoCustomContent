register_module_line('AWS S3 Radware', 'start', __line__())
CONSTANT_PACK_VERSION = '1.0.0'
demisto.debug('pack id = AWSS3Radware, pack version = 1.0.0')
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote_plus
import dateparser
from typing import Any, Optional
import json
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
import os
import gzip
import copy


class Client():
    def __init__(self, queue_url, aws_access_key_id, aws_secret_access_key, region_name, verify=False):
        self.sqs = boto3.client(
            "sqs",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
            verify=verify
            # config=session_config
        )

        self.s3 = boto3.client(
            "s3",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region_name,
            verify=verify
            # config=session_config
        )

        self.queue_url = queue_url


    def receive_sqs_messages(self, max_messages: int = 5, wait_time: int = 20, visibility_timeout: int = 300) -> list:
        response = self.sqs.receive_message(
            QueueUrl=self.queue_url,
            MaxNumberOfMessages=max_messages,
            WaitTimeSeconds=wait_time,
            VisibilityTimeout=visibility_timeout
        )

        return response.get("Messages", [])

    def delete_sqs_message(self, receipt_handle: str):
        self.sqs.delete_message(
            QueueUrl=self.queue_url,
            ReceiptHandle=receipt_handle
        )

    def download_s3_objects_from_message(self, message: dict, download_dir: str = "/tmp") -> list:
        downloaded_files = []

        body = json.loads(message["Body"])

        for record in body.get("Records", []):
            bucket = record["s3"]["bucket"]["name"]
            encoded_key = record["s3"]["object"]["key"]
            key = unquote_plus(encoded_key)

            local_file = os.path.join(download_dir, os.path.basename(key))
            self.s3.download_file(bucket, key, local_file)

            downloaded_files.append({
                "bucket": bucket,
                "key": key,
                "local_file": local_file
            })

        return downloaded_files


    def test_connection(self):
        """
        Test AWS credentials + SQS + S3 access
        """
        try:
            # test sts access
            sts = boto3.client(
                "sts",
                aws_access_key_id=self.sqs._request_signer._credentials.access_key,
                aws_secret_access_key=self.sqs._request_signer._credentials.secret_key,
                region_name=self.sqs.meta.region_name
            )
            sts.get_caller_identity()

            # test s3 access
            self.s3.list_buckets()

            # if all test pass then return successfull message as ok
            return "ok"

        except NoCredentialsError:
            raise Exception("Invalid AWS credentials")

        except EndpointConnectionError as e:
            raise Exception(f"Invalid AWS region or endpoint: {str(e)}")

        except ClientError as e:
            raise Exception(f"AWS permission error: {e.response['Error']['Message']}")

        except Exception as e:
            raise Exception(f"Error: {str(e)}")


def read_gz_json_array(file_path: str) -> list[dict]:
    with gzip.open(file_path, "rt", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Expected JSON array")

    return data


def fetch_events(client: Client, fetch_limit: int, last_run: dict[str, str], vendor: str, product: str, max_messages: int = 5):
    if not last_run:
        messages = client.receive_sqs_messages(max_messages=max_messages)

        for msg in messages:
            receipt_handle = msg["ReceiptHandle"]

            # download files from S3 bucket
            files = client.download_s3_objects_from_message(msg)

            last_run[receipt_handle] = files
        demisto.setLastRun(last_run)

    events_metadata = copy.deepcopy(last_run)
    for receipt_handle, files in events_metadata.items():
        for f in files:
            file_name = f['local_file']
            try:
                events = read_gz_json_array(file_name)
                # for event_batch in batch(events, fetch_limit):
                send_events_to_xsiam(events, vendor=vendor, product=product, should_update_health_module=True)
            except Exception as e:
                demisto.updateModuleHealth(f"Failed processing file {file_name}: {str(e)}")
                continue

            # update remove processed file from the context
            files_data = [file_data for file_data in files if file_data['local_file'] != file_name]

            if files_data:
                last_run[receipt_handle] = files_data
            else:
                last_run.pop(receipt_handle)
            demisto.setLastRun(last_run)

            # delete file from the tmp directory
            if os.path.exists(file_name):
                os.remove(file_name)

        # delete sql message
        client.delete_sqs_message(receipt_handle)


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()

    # Vendor and Product name for dataset
    vendor = params.get('vendor')
    product = params.get('product')

    # Get the credentials from integration parameters
    access_key_id = params.get('credentials', {}).get('identifier')
    secret_access_key = params.get('credentials', {}).get('password')
    region = params['region']
    account_id = params['account_id']
    queue_name = params['queue_name']

    # Format the url
    url = f"https://sqs.{region}.amazonaws.com/{account_id}/{queue_name}"

    use_ssl = params.get('secure', False)

    '''
    Inititate client class object to be used for sending API calls.
    '''
    client = Client(
        queue_url=url,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name=region,
        verify=use_ssl
    )

    command = demisto.command()
    try:
        fetch_limit = params.get("eventFetchLimit", 1000)

        if command == 'test-module':
            response = client.test_connection()
            return_results(response)

        elif command == 'fetch-events':
            last_run = demisto.getLastRun() or {}
            fetch_events(client, fetch_limit, last_run, vendor, product)

    except Exception as e:
        err_msg = f"Error in {get_integration_name()} Integration [{e}]"
        return_error(err_msg, error=e)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
register_module_line('AWS S3 Radware', 'end', __line__())
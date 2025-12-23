
import functools
from base64 import b64decode
from collections.abc import Callable, Generator
from multiprocessing import Process
from ssl import PROTOCOL_TLSv1_2, SSLContext, SSLError
from tempfile import NamedTemporaryFile
from urllib.parse import ParseResult, urlparse
import time
import os
import netaddr
import pytz
import werkzeug.urls
from flask import Flask, Response, jsonify, make_response, request
from gevent.pywsgi import WSGIServer
import base64
from functools import wraps

from requests.utils import requote_uri
from werkzeug.datastructures import Headers

""" GLOBAL VARIABLES """
INTEGRATION_NAME: str = "Akamai Server"
PAGE_SIZE = 1000
APP: Flask = Flask("demisto-akamai")
NAMESPACE_URI = "https://www.paloaltonetworks.com/cortex"
NAMESPACE = "cortex"


""" Log Handler """


class Handler:
    @staticmethod
    def write(msg: str):
        """
        Writes a log message to the Demisto server.
        Args:
            message: The log message to write

        """
        demisto.info(msg)


class ErrorHandler:
    @staticmethod
    def write(msg: str):
        """
        Writes a error message to the Demisto server.
        Args:
            message: The log message to write

        """
        demisto.error(f"wsgi error: {msg}")


DEMISTO_LOGGER: Handler = Handler()
ERROR_LOGGER: ErrorHandler = ErrorHandler()

""" TAXII Server """


class APIServer:
    def __init__(
        self,
        url_scheme: str,
        host: str,
        port: int,
        certificate: str,
        private_key: str,
        http_server: bool,
        credentials: dict
    ):
        """
        Class for a API Server configuration.
        Args:
            url_scheme: The URL scheme (http / https)
            host: The server address.
            port: The server port.
            collections: The JSON string of collections of indicator queries.
            certificate: The server certificate for SSL.
            private_key: The private key for SSL.
            http_server: Whether to use HTTP server (not SSL).
            credentials: The user credentials.
        """
        self.url_scheme = url_scheme
        self.host = host
        self.port = port
        self.certificate = certificate
        self.private_key = private_key
        self.http_server = http_server
        self.auth = None
        if credentials:
            self.auth = (credentials.get("identifier", ""), credentials.get("password", ""))



""" HELPER FUNCTIONS """


def get_calling_context():
    return demisto.callingContext.get("context", {})  # type: ignore[attr-defined]


def handle_long_running_error(error: str):
    """
    Handle errors in the long running process.
    Args:
        error: The error message.
    """
    demisto.error(error)
    demisto.updateModuleHealth(error)


def get_port(params: dict = demisto.params()) -> int:
    """
    Gets port from the integration parameters.
    """
    if not params.get("longRunningPort"):
        params["longRunningPort"] = "1111"
    try:
        port = int(params.get("longRunningPort", ""))
    except ValueError as e:
        raise ValueError(f"Invalid listen port - {e}")

    return port


def validate_credentials(f: Callable) -> Callable:
    """
    Wrapper function of HTTP requests to validate authentication headers.
    Args:
        f: The wrapped function.

    Returns:
        The function result (if the authentication is valid).
    """

    @wraps(f)
    def validate(*args, **kwargs):
        headers = request.headers.get("Authorization")
        credentials = headers

        if not credentials or not credentials.startswith("Basic "):
            return jsonify({"error": "Invalid authentication"}), 401

        encoded_credentials = credentials.split("Basic ")[1]
        credentials = base64.b64decode(encoded_credentials).decode("utf-8")
        if ":" not in credentials:
            return jsonify({"error": "Invalid authentication"}), 401

        credentials_list = credentials.split(":")
        if len(credentials_list) != 2:
            return jsonify({"error": "Invalid authentication"}), 401

        params = demisto.params()

        server_credentials: dict = params.get("credentials", None)
        server_username = server_credentials.get("identifier", "")
        server_password = server_credentials.get("password", "")

        username, password = credentials_list
        if not (username == server_username and password == server_password):
            return jsonify({"error": "Invalid authentication"}), 401

        return f(*args, **kwargs)

    return validate


""" ROUTE FUNCTIONS """


@APP.route("/logs", methods=["POST"])
@validate_credentials
def receive_logs() -> Response:
    """
    Route to receive the logs
    """
    try:
        log_data = request.get_json(force=True)
        # demisto.updateModuleHealth(log_data)
        # send_events_to_xsiam(log_data, vendor="akamai", product="custom")
        return jsonify({"status": "success", "message": "Log received"}), 200
    except Exception as e:
        error = f"Failed to parse the logs from response payload: {e!s}"
        handle_long_running_error(error)
        return jsonify({"error": str(e)}), 400


""" COMMAND FUNCTIONS """


def test_module(api_server: APIServer):
    run_server(api_server, is_test=True)
    return "ok"


def run_server(api_server: APIServer, is_test=False):
    """
    Start the api server.
    """

    certificate_path = ""
    private_key_path = ""
    ssl_args = {}

    try:
        if api_server.certificate and api_server.private_key and not api_server.http_server:
            certificate_file = NamedTemporaryFile(delete=False)
            certificate_path = certificate_file.name
            certificate_file.write(bytes(api_server.certificate, "utf-8"))
            certificate_file.close()

            private_key_file = NamedTemporaryFile(delete=False)
            private_key_path = private_key_file.name
            private_key_file.write(bytes(api_server.private_key, "utf-8"))
            private_key_file.close()
            context = SSLContext(PROTOCOL_TLSv1_2)
            context.load_cert_chain(certificate_path, private_key_path)
            ssl_args["ssl_context"] = context
            demisto.debug("Starting HTTPS Server")
        else:
            demisto.debug("Starting HTTP Server")

        wsgi_server = WSGIServer(("0.0.0.0", api_server.port), APP, **ssl_args, log=DEMISTO_LOGGER, error_log=ERROR_LOGGER)
        if is_test:
            server_process = Process(target=wsgi_server.serve_forever)
            server_process.start()
            time.sleep(5)
            server_process.terminate()
        else:
            demisto.updateModuleHealth("")
            wsgi_server.serve_forever()
    except SSLError as e:
        ssl_err_message = f"Failed to validate certificate and/or private key: {e!s}"
        handle_long_running_error(ssl_err_message)
        raise ValueError(ssl_err_message)
    except Exception as e:
        handle_long_running_error(f"An error occurred: {e!s}")
        raise ValueError(str(e))
    finally:
        if certificate_path:
            os.unlink(certificate_path)
        if private_key_path:
            os.unlink(private_key_path)


def main():
    """
    Main
    """
    params = demisto.params()
    command = demisto.command()

    certificate: str = params.get("certificate", "")
    private_key: str = params.get("key", "")
    credentials: dict = params.get("credentials", None)
    http_server = True
    if (certificate and not private_key) or (private_key and not certificate):
        raise ValueError("When using HTTPS connection, both certificate and private key must be provided.")
    elif certificate and private_key:
        http_server = False

    commands: dict = {}
    try:
        port = get_port(params)
        server_links = demisto.demistoUrls()
        server_link_parts: ParseResult = urlparse(server_links.get("server"))

        scheme = "http"
        host_name = server_link_parts.hostname

        if is_xsiam() or is_platform():
            # Replace the 'xdr' with 'crtx' in the hostname of XSIAM tenants
            # This substitution is related to this platform ticket: https://jira-dc.paloaltonetworks.com/browse/CIAC-12256.
            host_name = str(server_link_parts.hostname).replace(".xdr", ".crtx", 1)
        if not http_server:
            scheme = "https"

        SERVER = APIServer(
            scheme, str(host_name), port, certificate, private_key, http_server, credentials
        )
        if command == "test-module":
            return_results(test_module(SERVER))
        elif command == "long-running-execution":
            run_server(SERVER)

    except Exception as e:
        err_msg = f"Error in {INTEGRATION_NAME} Integration [{e}]"
        return_error(err_msg)


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()

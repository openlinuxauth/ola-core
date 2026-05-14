#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import socket
import json
import sys
import os
import uuid

DEFAULT_SOCKET_PATH = "/run/ola/ola.sock"
PROTOCOL_VERSION = 1
MAX_RESPONSE_BYTES = 512 * 1024


def _client_error(request_id, message):
    return {"id": request_id, "result": None, "error": message}


def _validate_response(response, expected_id):
    if not isinstance(response, dict):
        return _client_error(expected_id, "Response must be a JSON object")

    if response.get("version") != PROTOCOL_VERSION:
        return _client_error(expected_id, "Protocol version mismatch")

    has_result = response.get("result") is not None
    has_error = response.get("error") is not None
    if has_result == has_error:
        return _client_error(expected_id, "Response must contain exactly one of result or error")

    if has_error and not isinstance(response["error"], str):
        return _client_error(expected_id, "Response error must be a string")

    response_id = response.get("id")
    if response_id == expected_id:
        return response

    if response_id is None and has_error:
        return _client_error(expected_id, response["error"])

    return _client_error(expected_id, "Response id mismatch")


def default_timeout():
    raw = os.environ.get("OLA_CLIENT_TIMEOUT", "5.0")
    try:
        timeout = float(raw)
    except ValueError as exc:
        raise ValueError("OLA_CLIENT_TIMEOUT must be a float") from exc
    if timeout <= 0:
        raise ValueError("OLA_CLIENT_TIMEOUT must be greater than zero")
    return timeout


def default_socket_path():
    return os.environ.get("OLA_SOCKET", DEFAULT_SOCKET_PATH)


class OlaClient:
    def __init__(self, socket_path=None, timeout=None):
        self.socket_path = default_socket_path() if socket_path is None else socket_path
        self.timeout = default_timeout() if timeout is None else timeout

    def _send(self, method, params=None):
        req = {
            "version": PROTOCOL_VERSION,
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params or {},
        }

        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)

        try:
            s.connect(self.socket_path)
        except Exception as e:
            return _client_error(req["id"], f"Connection failed: {str(e)}")

        try:
            msg = json.dumps(req) + "\n"
            s.sendall(msg.encode("utf-8"))

            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > MAX_RESPONSE_BYTES:
                    return _client_error(req["id"], "Response too large")
                if b"\n" in chunk:
                    break

            if not data:
                return _client_error(req["id"], "Empty response from server")

            line = data.split(b"\n", 1)[0]
            try:
                response = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError as e:
                return _client_error(req["id"], f"Invalid response JSON: {e}")
            return _validate_response(response, req["id"])

        except socket.timeout:
            return _client_error(req["id"], "Request timed out")
        except Exception as e:
            return _client_error(req["id"], f"Client error: {e}")
        finally:
            s.close()

    def ping(self):
        return self._send("ping")

    def list_methods(self):
        return self._send("list_methods")

    def verify_once(self, method=None, uid=None):
        params = {}
        if method is not None:
            params["method"] = method
        if uid is not None:
            params["uid"] = uid
        return self._send("verify_once", params)

    def status(self):
        return self._send("status")


def main():
    client = OlaClient()
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "ping":
            print(client.ping())
        elif cmd == "list_methods":
            print(client.list_methods())
        elif cmd == "verify_once":
            method = sys.argv[2] if len(sys.argv) > 2 else None
            print(client.verify_once(method=method))
        elif cmd == "status":
            print(client.status())
        else:
            print(f"Unknown command: {cmd}")
    else:
        print("Usage: python3 ola_client.py [ping|list_methods|verify_once [method]|status]")

if __name__ == "__main__":
    main()

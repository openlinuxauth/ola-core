#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import json
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from ola_client import OlaClient, PROTOCOL_VERSION, default_socket_path


def run_client(response_for_request):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "ola.sock")
        errors = []

        def server():
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                    listener.bind(path)
                    listener.listen(1)
                    conn, _ = listener.accept()
                    with conn:
                        request = json.loads(conn.recv(4096).decode("utf-8"))
                        conn.sendall(response_for_request(request))
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=server)
        thread.start()
        deadline = time.monotonic() + 1.0
        while not os.path.exists(path):
            if errors:
                raise errors[0]
            if time.monotonic() > deadline:
                raise TimeoutError("test server did not create socket")
            time.sleep(0.01)

        result = OlaClient(socket_path=path, timeout=1.0).ping()
        thread.join(timeout=1.0)
        if thread.is_alive():
            raise TimeoutError("test server did not finish")
        if errors:
            raise errors[0]
        return result


def json_response(request, **fields):
    response = {
        "version": PROTOCOL_VERSION,
        "id": request["id"],
        "result": {"ok": True},
        "error": None,
    }
    response.update(fields)
    return (json.dumps(response) + "\n").encode("utf-8")


class OlaClientTests(unittest.TestCase):
    def test_socket_path_env_is_used(self):
        with patch.dict(os.environ, {"OLA_SOCKET_PATH": "/tmp/path.sock"}, clear=True):
            self.assertEqual(default_socket_path(), "/tmp/path.sock")

    def test_legacy_socket_env_is_used(self):
        with patch.dict(os.environ, {"OLA_SOCKET": "/tmp/legacy.sock"}, clear=True):
            self.assertEqual(default_socket_path(), "/tmp/legacy.sock")

    def test_socket_path_env_wins_over_legacy(self):
        with patch.dict(
            os.environ,
            {"OLA_SOCKET_PATH": "/tmp/path.sock", "OLA_SOCKET": "/tmp/legacy.sock"},
            clear=True,
        ):
            self.assertEqual(default_socket_path(), "/tmp/path.sock")

    def test_valid_response_passes(self):
        result = run_client(lambda request: json_response(request))

        self.assertIsNone(result["error"])
        self.assertEqual(result["result"]["ok"], True)

    def test_wrong_version_fails(self):
        result = run_client(lambda request: json_response(request, version=2))

        self.assertEqual(result["error"], "Protocol version mismatch")

    def test_wrong_id_fails(self):
        result = run_client(lambda request: json_response(request, id="wrong"))

        self.assertEqual(result["error"], "Response id mismatch")

    def test_null_id_error_is_preserved(self):
        result = run_client(
            lambda request: json_response(
                request,
                id=None,
                result=None,
                error="Rate limit exceeded",
            )
        )

        self.assertEqual(result["error"], "Rate limit exceeded")
        self.assertIsNone(result["result"])

    def test_null_id_result_fails(self):
        result = run_client(lambda request: json_response(request, id=None))

        self.assertEqual(result["error"], "Response id mismatch")

    def test_invalid_json_fails(self):
        result = run_client(lambda request: b"not json\n")

        self.assertIn("Invalid response JSON", result["error"])

    def test_non_object_json_fails(self):
        result = run_client(lambda request: b"[]\n")

        self.assertEqual(result["error"], "Response must be a JSON object")

    def test_result_and_error_fails(self):
        result = run_client(lambda request: json_response(request, error="bad"))

        self.assertEqual(
            result["error"],
            "Response must contain exactly one of result or error",
        )

    def test_missing_result_and_error_fails(self):
        result = run_client(
            lambda request: json_response(request, result=None, error=None)
        )

        self.assertEqual(
            result["error"],
            "Response must contain exactly one of result or error",
        )


if __name__ == "__main__":
    unittest.main()

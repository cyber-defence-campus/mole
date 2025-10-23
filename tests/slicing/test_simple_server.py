from __future__ import annotations
from tests.slicing.conftest import TestSlicing
from typing import List


class TestSimpleServer(TestSlicing):
    def test_simple_http_server_01(
        self, filenames: List[str] = ["simple_http_server-01"]
    ) -> None:
        self.assert_paths(
            src=[("recv", 2)],
            snk=[("system", 1)],
            call_chains=[["handle_get_request"], ["handle_post_request"]],
            filenames=filenames,
        )
        return

    def test_simple_http_server_02(
        self, filenames: List[str] = ["simple_http_server-02"]
    ) -> None:
        self.assert_paths(
            src=[("recv", 2)],
            snk=[("system", 1)],
            call_chains=[
                ["execute_cgi_command", "handle_get_request", "receive_data"],
                ["execute_cgi_command", "handle_post_request", "receive_data"],
            ],
            filenames=filenames,
        )
        return

    def test_simple_http_server_03(
        self, filenames: List[str] = ["simple_http_server-03"]
    ) -> None:
        self.assert_paths(
            src=[("recv", 2)],
            snk=[("system", 1)],
            call_chains=[
                [
                    "execute_cgi_command",
                    "wrap_and_execute",
                    "process_request",
                    "handle_get_request",
                    "receive_data",
                ],
                [
                    "execute_cgi_command",
                    "wrap_and_execute",
                    "process_request",
                    "handle_post_request",
                    "receive_data",
                ],
                [
                    "execute_cgi_command",
                    "wrap_and_execute",
                    "process_request",
                    "handle_put_request",
                    "receive_data",
                ],
                [
                    "execute_cgi_command",
                    "wrap_and_execute",
                    "process_request",
                    "handle_delete_request",
                    "receive_data",
                ],
            ],
            filenames=filenames,
        )
        return

    def test_simple_http_server_04(
        self, filenames: List[str] = ["simple_http_server-04"]
    ) -> None:
        self.assert_paths(
            src=[("recv", 2)],
            snk=[("system", 1)],
            call_chains=[
                [
                    "execute_cgi_command",
                    "process_post_request",
                    "handle_post_request",
                    "receive_data",
                ],
                [
                    "execute_cgi_command",
                    "process_post_request",
                    "handle_post_request",
                    "receive_data",
                ],
                [
                    "execute_cgi_command",
                    "process_post_request",
                    "handle_post_request",
                    "receive_data",
                ],
                [
                    "execute_cgi_command",
                    "process_post_request",
                    "handle_post_request",
                    "receive_data",
                ],
            ],
            filenames=filenames,
        )
        return

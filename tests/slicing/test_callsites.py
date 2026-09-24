from __future__ import annotations
from mole.common.log import Logger
from mole.data.config import (
    Category,
    Configuration,
    Function,
    Library,
)
from mole.services.config import ConfigService
from tests.slicing.conftest import TestSlicing
from typing import Generator, IO, List
import pytest
import tempfile


@pytest.fixture
def temp_file() -> Generator[IO[str], None, None]:
    """Provides a temporary file for testing."""
    tf = tempfile.NamedTemporaryFile(mode="w+", delete=False)
    yield tf
    tf.close()
    return


@pytest.fixture
def config_service() -> ConfigService:
    """Provides a ConfigService instance."""
    return ConfigService(Logger())


@pytest.fixture
def test_config() -> Configuration:
    """Provides a test Configuration object."""
    return Configuration(
        taint_model={
            "libc": Library(
                name="libc",
                categories={
                    "Networks": Category(
                        name="Networks",
                        functions={
                            "recv": Function(
                                name="recv",
                                symbols=["recv", "_recv", "__builtin_recv"],
                                synopsis="ssize_t recv (int socket, void *buffer, size_t size, int flags)",
                                src_enabled=True,
                                src_par_slice="i == 2",
                                snk_enabled=False,
                                snk_par_slice="False",
                                fix_enabled=False,
                            )
                        },
                    ),
                    "Process Execution": Category(
                        name="Process Execution",
                        functions={
                            "system": Function(
                                name="system",
                                symbols=["system", "_system", "__builtin_system"],
                                synopsis="int system (const char *command)",
                                src_enabled=False,
                                src_par_slice="False",
                                snk_enabled=True,
                                snk_par_slice="i == 1",
                                fix_enabled=False,
                            )
                        },
                    ),
                },
            ),
            "unit-test": Library(
                name="unit-test",
                categories={
                    "Fixers": Category(
                        name="Fixers",
                        functions={
                            "my_exec": Function(
                                name="my_exec",
                                symbols=["my_exec"],
                                synopsis="void my_exec(char* cmd)",
                                fix_enabled=True,
                            )
                        },
                    )
                },
            ),
        },
    )


class TestCallsites(TestSlicing):
    def test_callsites_01(
        self,
        temp_file: IO[str],
        config_service: ConfigService,
        test_config: Configuration,
        filenames: List[str] = ["simple_http_server-01"],
    ) -> None:
        # Set explicit source call sites
        test_config.taint_model["libc"].categories["Networks"].functions[
            "recv"
        ].src_callsites = set([67840, 4199426])
        # Export configuration to temporary file
        config_service.export_config(test_config, temp_file.name)
        # Use temporary file as configuration file
        self._config_file = temp_file.name
        # Assert paths
        self.assert_paths(
            srcs=[("recv", 2)],
            snks=[("system", 1)],
            call_chains=[["handle_get_request"]],
            filenames=filenames,
        )
        return

    def test_callsites_02(
        self,
        temp_file: IO[str],
        config_service: ConfigService,
        test_config: Configuration,
        filenames: List[str] = ["simple_http_server-01"],
    ) -> None:
        # Set explicit sink call sites
        test_config.taint_model["libc"].categories["Process Execution"].functions[
            "system"
        ].snk_callsites = set([68176, 4199727])
        # Export configuration to temporary file
        config_service.export_config(test_config, temp_file.name)
        # Use temporary file as configuration file
        self._config_file = temp_file.name
        # Assert paths
        self.assert_paths(
            srcs=[("recv", 2)],
            snks=[("system", 1)],
            call_chains=[["handle_post_request"]],
            filenames=filenames,
        )
        return

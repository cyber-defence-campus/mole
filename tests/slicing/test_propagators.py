from __future__ import annotations
from mole.common.log import Logger
from mole.data.config import (
    Category,
    CheckboxSetting,
    Configuration,
    Library,
    PropagatorFunction,
    SinkFunction,
    SourceFunction,
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
        sources={
            "libc": Library(
                name="libc",
                categories={
                    "Environment Accesses": Category(
                        name="Environment Accesses",
                        functions={
                            "getenv": SourceFunction(
                                name="getenv",
                                symbols=["getenv", "_getenv", "__builtin_getenv"],
                                synopsis="char * getenv(const char *name)",
                                enabled=True,
                                par_cnt="i == 1",
                                par_slice="False",
                            )
                        },
                    )
                },
            ),
        },
        sinks={
            "libc": Library(
                name="libc",
                categories={
                    "Process Execution": Category(
                        name="Process Execution",
                        functions={
                            "system": SinkFunction(
                                name="system",
                                symbols=["system", "_system", "__builtin_system"],
                                synopsis="int system (const char *command)",
                                enabled=True,
                                par_cnt="i == 1",
                                par_slice="True",
                            )
                        },
                    )
                },
            ),
        },
        propagators={
            "unit-test": Library(
                name="unit-test",
                categories={
                    "Propagators": Category(
                        name="Propagators",
                        functions={
                            "my_exec": PropagatorFunction(
                                name="my_exec",
                                symbols=["my_exec"],
                                synopsis="void my_exec(char* cmd)",
                                par_cnt="i == 1",
                            )
                        },
                    )
                },
            ),
        },
        settings={
            "fix_func_type": CheckboxSetting(
                name="fix_func_type",
                value=True,
                help="whether to fix types of source/sink functions before slicing",
            ),
        },
    )


class TestPropagators(TestSlicing):
    def test_propagator_01(
        self,
        temp_file: IO[str],
        config_service: ConfigService,
        test_config: Configuration,
        filenames: List[str] = ["propagator-01"],
    ) -> None:
        # Export configuration to temporary file
        config_service.export_config(test_config, temp_file.name)
        # Use temporary file as configuration file
        self._config_file = temp_file.name
        #
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[
                ["my_exec", "main"],
            ],
            filenames=filenames,
        )
        return

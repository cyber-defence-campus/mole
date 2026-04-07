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
                    "Environment Accesses": Category(
                        name="Environment Accesses",
                        functions={
                            "getenv": Function(
                                name="getenv",
                                symbols=["getenv", "_getenv", "__builtin_getenv"],
                                synopsis="char * getenv(const char *name)",
                                src_enabled=True,
                                src_par_slice="False",
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
                    "Propagators": Category(
                        name="Propagators",
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


class TestFixers(TestSlicing):
    def test_fixer_01(
        self,
        temp_file: IO[str],
        config_service: ConfigService,
        test_config: Configuration,
        filenames: List[str] = ["fixer-01"],
    ) -> None:
        # Export configuration to temporary file
        config_service.export_config(test_config, temp_file.name)
        # Use temporary file as configuration file
        self._config_file = temp_file.name
        # Assert paths
        self.assert_paths(
            srcs=[("getenv", None)],
            snks=[("system", 1)],
            call_chains=[
                ["my_exec", "main"],
            ],
            filenames=filenames,
        )
        return

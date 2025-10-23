from __future__ import annotations
from mole.core.data import Category, Configuration, Library
from mole.core.data import SinkFunction, SourceFunction
from mole.core.data import (
    ComboboxSetting,
    DoubleSpinboxSetting,
    SpinboxSetting,
    TextSetting,
)
from mole.services.config import ConfigService
from typing import Generator, IO
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
    return ConfigService()


@pytest.fixture
def test_config() -> Configuration:
    """Provides a test Configuration object."""
    return Configuration(
        sources={
            "manual": Library(name="manual", categories={}),
            "libc": Library(
                name="libc",
                categories={
                    "Environment Accesses": Category(
                        name="Environment Accesses",
                        functions={
                            "getenv": SourceFunction(
                                name="getenv",
                                symbols=["getenv", "__builtin_getenv"],
                                synopsis="char* getenv(const char* name)",
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
            "manual": Library(name="manual", categories={}),
            "libc": Library(
                name="libc",
                categories={
                    "Memory Copy": Category(
                        name="Memory Copy",
                        functions={
                            "memcpy": SinkFunction(
                                name="memcpy",
                                symbols=["memcpy", "__builtin_memcpy"],
                                synopsis="void* memcpy(void* dest, const void* src, size_t n)",
                                enabled=True,
                                par_cnt="i == 3",
                                par_slice="True",
                            )
                        },
                    )
                },
            ),
        },
        settings={
            "max_workers": SpinboxSetting(
                name="max_workers",
                value=-1,
                min_value=-1,
                max_value=256,
                help="maximum number of worker thread that backward slicing uses",
            ),
            "max_call_level": SpinboxSetting(
                name="max_call_level",
                value=5,
                min_value=-1,
                max_value=99,
                help="backward slicing visits called functions up to the given level",
            ),
            "max_slice_depth": SpinboxSetting(
                name="max_slice_depth",
                value=-1,
                min_value=-1,
                max_value=9999,
                help="maximum slice depth to stop the search",
            ),
            "max_memory_slice_depth": SpinboxSetting(
                name="max_memory_slice_depth",
                value=-1,
                min_value=-1,
                max_value=9999,
                help="maximum memory slice depth to stop the search",
            ),
            "src_highlight_color": ComboboxSetting(
                name="src_highlight_color",
                value="Orange",
                items=[
                    "Blue",
                    "Green",
                    "Cyan",
                    "Red",
                    "Magenta",
                    "Yellow",
                    "Orange",
                ],
                help="color used to highlight instructions originating from slicing a source function",
            ),
            "snk_highlight_color": ComboboxSetting(
                name="snk_highlight_color",
                value="Red",
                items=[
                    "Blue",
                    "Green",
                    "Cyan",
                    "Red",
                    "Magenta",
                    "Yellow",
                    "Orange",
                ],
                help="color used to highlight instructions originating from slicing a sink function",
            ),
            "path_grouping": ComboboxSetting(
                name="path_grouping",
                value="Call Graph",
                items=["Call Graph", "Source / Sink", "None"],
                help="strategy used to group paths",
            ),
            "openai_base_url": TextSetting(
                name="openai_base_url",
                value="https://api.openai.com/v1",
                help="OpenAI API base URL",
            ),
            "openai_api_key": TextSetting(
                name="openai_api_key",
                value="",
                help="OpenAI API key",
            ),
            "openai_model": TextSetting(
                name="openai_model",
                value="o4-mini",
                help="OpenAI model",
            ),
            "max_turns": SpinboxSetting(
                name="max_turns",
                value=10,
                min_value=2,
                max_value=256,
                help="maximum number of turns in a conversation with the AI",
            ),
            "max_completion_tokens": SpinboxSetting(
                name="max_completion_tokens",
                value=4096,
                min_value=-1,
                max_value=100000,
                help="maximum number of tokens in a completion",
            ),
            "temperature": DoubleSpinboxSetting(
                name="temperature",
                value=1.0,
                min_value=0.0,
                max_value=2.0,
                help="the sampling temperature to use",
            ),
        },
    )


class TestData:
    """
    This class implements unit tests for the data classes.
    """

    def test_serialize_configuration(
        self,
        temp_file: IO[str],
        config_service: ConfigService,
        test_config: Configuration,
    ) -> None:
        ori_config: Configuration = test_config
        # Export configuration to temporary file (serialize)
        config_service.export_config(ori_config, temp_file.name)
        # Load configuration from temporary file (deserialize)
        temp_file.seek(0)
        des_config = config_service.import_config(temp_file.name)
        # Assert
        assert ori_config == des_config, "Serialization error of 'Configuration'"
        return

from __future__ import annotations
from mole.core.data import Category, Configuration, Library
from mole.core.data import SinkFunction, SourceFunction
from mole.core.data import ComboboxSetting, SpinboxSetting, TextSetting
import tempfile
import unittest
import yaml


class TestData(unittest.TestCase):
    """
    This class implements unit tests for the data classes.
    """

    def setUp(self) -> None:
        self.tf = tempfile.NamedTemporaryFile(mode="w+", delete=False)
        self.config = Configuration(
            sources={
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
                                    par_dataflow="False",
                                    par_slice="False",
                                )
                            },
                        )
                    },
                )
            },
            sinks={
                "libc": Library(
                    "libc",
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
                                    par_dataflow="False",
                                    par_slice="True",
                                )
                            },
                        )
                    },
                )
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
                    value=3,
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
                        "White",
                        "Black",
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
                        "White",
                        "Black",
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
            },
        )
        return

    def test_serialize_configuration(self) -> None:
        ori_config: Configuration = self.config
        # Serialize
        yaml.safe_dump(
            ori_config.to_dict(),
            self.tf,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8",
        )
        # Deserialize
        self.tf.seek(0)
        des_config = Configuration(**yaml.safe_load(self.tf))
        # Assert
        self.assertEqual(
            ori_config, des_config, "Serialization error of 'Configuration'"
        )
        return

    def test_serialize_library(self) -> None:
        ori_lib: Library = self.config.sources["libc"]
        # Serialize
        yaml.safe_dump(
            ori_lib.to_dict(),
            self.tf,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8",
        )
        # Deserialize
        self.tf.seek(0)
        des_lib = Library(**yaml.safe_load(self.tf))
        # Assert
        self.assertEqual(ori_lib, des_lib, "Serialization error of 'Library'")
        return

    def test_serialize_category(self) -> None:
        ori_category: Category = self.config.sources["libc"].categories[
            "Environment Accesses"
        ]
        # Serialize
        yaml.safe_dump(
            ori_category.to_dict(),
            self.tf,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8",
        )
        # Deserialize
        self.tf.seek(0)
        des_category = Category(**yaml.safe_load(self.tf))
        # Assert
        self.assertEqual(
            ori_category, des_category, "Serialization error of 'Category'"
        )
        return

    def test_serialize_sources(self) -> None:
        ori_source: SourceFunction = (
            self.config.sources["libc"]
            .categories["Environment Accesses"]
            .functions["getenv"]
        )
        # Serialize
        yaml.safe_dump(
            ori_source.to_dict(),
            self.tf,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8",
        )
        # Deserialize
        self.tf.seek(0)
        des_source = SourceFunction(**yaml.safe_load(self.tf))
        # Assert
        self.assertEqual(
            ori_source, des_source, "Serialization error of 'SourceFunction'"
        )
        return

    def test_serialize_sinks(self) -> None:
        ori_sink: SinkFunction = (
            self.config.sinks["libc"].categories["Memory Copy"].functions["memcpy"]
        )
        # Serialize
        yaml.safe_dump(
            ori_sink.to_dict(),
            self.tf,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8",
        )
        # Deserialize
        self.tf.seek(0)
        des_sink = SinkFunction(**yaml.safe_load(self.tf))
        # Assert
        self.assertEqual(ori_sink, des_sink, "Serialization error of 'SinkFunction'")
        return

    def test_serialize_spinbox_settings(self) -> None:
        for name in [
            "max_workers",
            "max_call_level",
            "max_slice_depth",
            "max_turns",
            "max_completion_tokens",
        ]:
            ori_set: SpinboxSetting = self.config.settings.get(name, None)
            # Serialize
            self.tf.seek(0)
            self.tf.truncate(0)
            yaml.safe_dump(
                ori_set.to_dict(),
                self.tf,
                sort_keys=False,
                default_style=None,
                default_flow_style=None,
                encoding="utf-8",
            )
            # Deserialize
            self.tf.seek(0)
            des_set = SpinboxSetting(**yaml.safe_load(self.tf))
            # Assert
            self.assertEqual(
                ori_set, des_set, "Serialization error of 'SpinboxSetting'"
            )
        return

    def test_serialize_combobox_settings(self) -> None:
        for name in ["src_highlight_color", "snk_highlight_color", "path_grouping"]:
            ori_set: ComboboxSetting = self.config.settings.get(name, None)
            # Serialize
            self.tf.seek(0)
            self.tf.truncate(0)
            yaml.safe_dump(
                ori_set.to_dict(),
                self.tf,
                sort_keys=False,
                default_style=None,
                default_flow_style=None,
                encoding="utf-8",
            )
            # Deserialize
            self.tf.seek(0)
            des_set = ComboboxSetting(**yaml.safe_load(self.tf))
            # Assert
            self.assertEqual(
                ori_set, des_set, "Serialization error of 'ComboboxSetting'"
            )
        return

    def test_serialize_text_settings(self) -> None:
        for name in ["openai_base_url", "openai_api_key", "openai_model"]:
            ori_set: TextSetting = self.config.settings.get(name, None)
            # Serialize
            self.tf.seek(0)
            self.tf.truncate(0)
            yaml.safe_dump(
                ori_set.to_dict(),
                self.tf,
                sort_keys=False,
                default_style=None,
                default_flow_style=None,
                encoding="utf-8",
            )
            # Deserialize
            self.tf.seek(0)
            des_set = TextSetting(**yaml.safe_load(self.tf))
            # Assert
            self.assertEqual(ori_set, des_set, "Serialization error of 'TextSetting'")
        return

    def tearDown(self) -> None:
        self.tf.close()
        return

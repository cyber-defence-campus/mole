from __future__           import annotations
from mole.core.controller import Controller
from mole.core.data       import *
import tempfile
import unittest
import yaml


class TestData(unittest.TestCase):
    """
    This class implements unit tests for the data classes.
    """

    def setUp(self) -> None:
        self.tf = tempfile.NamedTemporaryFile(mode="w+", delete=False)
        self.ctr = Controller(runs_headless=True)
        self.conf = Configuration(
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
                                    par_slice="False"
                                )
                            }
                        )
                    }
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
                                    par_slice="True"
                                )
                            }
                        )
                    }
                )
            },
            settings={
                "max_workers": SpinboxSetting(
                    name="max_workers",
                    value=-1,
                    min_value=-1,
                    max_value=256,
                    help="maximum number of worker thread that backward slicing uses"
                ),
                "max_call_level": SpinboxSetting(
                    name="max_call_level",
                    value=3,
                    min_value=-1,
                    max_value=99,
                    help="backward slicing visits called functions up to the given level"
                ),
                "max_slice_depth": SpinboxSetting(
                    name="max_slice_depth",
                    value=-1,
                    min_value=-1,
                    max_value=9999,
                    help="maximum slice depth to stop the search"
                ),
                "highlight_color": ComboboxSetting(
                    name="highlight_color",
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
                        "Black"
                    ],
                    help="color used to highlight paths"
                )
            }
        )
        return
    
    def test_serialize_configuration(self) -> None:
        conf = self.conf
        # Serialize
        yaml.safe_dump(
            conf.to_dict(),
            self.tf,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8"
        )
        # Deserialize
        self.tf.seek(0)
        ydoc = yaml.safe_load(self.tf)
        # Assert
        self.assertEqual(ydoc, conf, "Serialization error of 'Configuration'")
        return
    
    def test_serialize_library(self) -> None:
        lib = self.conf.sources["libc"]
        # Serialize
        yaml.safe_dump(
            lib.to_dict(),
            self.tf,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8"
        )
        # Deserialize
        self.tf.seek(0)
        ydoc = yaml.safe_load(self.tf)
        # Assert
        self.assertEqual(ydoc, lib, "Serialization error of 'Library'")
        return
    
    def test_serialize_category(self) -> None:
        category = self.conf.sources["libc"].categories["Environment Accesses"]
        # Serialize
        yaml.safe_dump(
            category.to_dict(),
            self.tf,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8"
        )
        # Deserialize
        self.tf.seek(0)
        ydoc = yaml.safe_load(self.tf)
        # Assert
        self.assertEqual(ydoc, category, "Serialization error of 'Category'")
        return
    
    def test_serialize_sources(self) -> None:
        source = self.conf.sources["libc"].categories["Environment Accesses"].functions["getenv"]
        # Serialize
        yaml.safe_dump(
            source.to_dict(),
            self.tf,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8"
        )
        # Deserialize
        self.tf.seek(0)
        ydoc = yaml.safe_load(self.tf)
        # Assert
        self.assertEqual(ydoc, source, "Serialization error of 'SourceFunction'")
        return

    def test_serialize_sinks(self) -> None:
        sink = self.conf.sinks["libc"].categories["Memory Copy"].functions["memcpy"]
        # Serialize
        yaml.safe_dump(
            sink.to_dict(),
            self.tf,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8"
        )
        # Deserialize
        self.tf.seek(0)
        ydoc = yaml.safe_load(self.tf)
        # Assert
        self.assertEqual(ydoc, sink, "Serialization error of 'SinkFunction'")
        return
    
    def test_serialize_spinbox_settings(self) -> None:
        settings = {
            "max_workers": self.conf.settings["max_workers"].to_dict(),
            "max_call_level": self.conf.settings["max_call_level"].to_dict(),
            "max_slice_depth": self.conf.settings["max_slice_depth"].to_dict()
        }

        # Serialize
        yaml.safe_dump(
            settings,
            self.tf,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8"
        )
        # Deserialize
        self.tf.seek(0)
        ydoc = yaml.safe_load(self.tf)
        # Assert
        self.assertEqual(ydoc, settings, "Serialization error of 'SpinboxSetting'")
        return
    
    def test_serialize_combobox_settings(self) -> None:
        setting = self.conf.settings["highlight_color"]
        # Serialize
        yaml.safe_dump(
            setting.to_dict(),
            self.tf,
            sort_keys=False,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8"
        )
        # Deserialize
        self.tf.seek(0)
        ydoc = yaml.safe_load(self.tf)
        # Assert
        self.assertEqual(ydoc, setting, "Serialization error of 'ComboboxSetting'")
        return
    
    def tearDown(self) -> None:
        self.tf.close()
        return
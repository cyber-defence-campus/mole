import os
import unittest
from typing               import List

from mole.common.log      import Logger
from mole.core.controller import Controller

def load_files(names: List[str]) -> List[str]:
    """
    This function returns all files in the `testcases` directory matching `name` but ignoring the
    file extension.
    """
    directory = os.path.join(os.path.dirname(__file__), "bin")
    files = []
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            if os.path.splitext(filename)[0] in names:
                files.append(os.path.join(dirpath, filename))
    return files




class TestCase(unittest.TestCase):
    """
    This class implements unit tests to test backward slicing for finding interesting code paths.
    """

    def setUp(self) -> None:
        # Initialize controller to operate in headless mode
        self.ctr = Controller(
            runs_headless=True,
            log=Logger(
                runs_headless=True,
                level="debug"
            )
        ).init()
        return

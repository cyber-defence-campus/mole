# Tests
This directory contains the test suite for the *Mole* project.
## Build Test Binaries
Before running the tests, you must first built the test binaries. Navigate to the tests data directory:
```bash
cd tests/data/
```
Then, compile all test binaries:
```bash
make all
```
To cross-compile the test binaries for a specific target architecture, specify the appropriate compilers. You may also define a custom file extension to distinguish the resulting binaries. For example:
```bash
CC=arm-linux-gcc CXX=arm-linux-g++ EXT=.linux-armv7 make all
```
## Run Tests
Before running the tests, make sure you are back in the *Mole* project's root directory:
```bash
cd ../../
```
#### Run All Tests
```bash
pytest
```
#### Run Specific Test File
```bash
pytest tests/test_data.py
pytest tests/slicing/test_pointer.py
```
#### Run Specific Test Class or Method
```bash
pytest tests/slicing/test_pointer.py::TestPointerAnalysis
pytest tests/slicing/test_pointer.py::TestPointerAnalysis::test_pointer_analysis_01
```
#### Run Tests for a Specific Architecture
To run tests only on binaries built for a specific architecture, set the `EXT` parameter to match the extension used during compilation:
```bash
EXT=".linux-armv7" pytest
```
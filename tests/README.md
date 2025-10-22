# Tests
This directory contains the test suite for the *Mole* project.
## Build Test Binaries
Before running tests, compile the test binaries:
```bash
cd tests/data/
make all
```
To cross-compile the binaries for a specific target architecture:
```bash
CC=arm-linux-gcc CXX=arm-linux-g++ EXT=.linux-armv7 make
```
## Run Tests
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
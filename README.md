[![Publish Release](https://github.com/pdamian/mole/actions/workflows/release.yml/badge.svg)](https://github.com/pdamian/mole/actions/workflows/release.yml)
# Mole

<p align="center">
  <img src="https://drive.google.com/uc?export=view&id=1oToYEJyJOJtT9fgl7Pm4DuVloZGod5MO" style="width: 256px; max-width: 100%; height: auto" alt="Mole Logo"/>
</p>

*Mole* is a *Binary Ninja* plugin that tries to identify **interesting paths** (from sources to
sinks) using **static backward slicing**. The plugin can be run both in *Binary Ninja* and in
headless mode.
## Installation
In the following, we assume that the variables `$BINJA_BIN` and `$BINJA_USR` point to your
*Binary Ninja*'s [binary path](https://docs.binary.ninja/guide/index.html#binary-path) and
[user folder](https://docs.binary.ninja/guide/index.html#user-folder), respectively.

Clone the *Mole* plugin to your *Binary Ninja*'s user folder:
```shell
cd $BINJA_USR/plugins/
git clone https://github.com/pdamian/mole.git && cd mole/
```
### Standard
Create and activate a new Python virtual environment for *Mole* (optional, but recommended):
```shell
python3 -m venv venv/mole
source venv/mole/bin/activate
```

Install *Binary Ninja*'s Python [API](https://docs.binary.ninja/dev/batch.html#install-the-api):
```shell
python $BINJA_BIN/scripts/install_api.py
```

Install *Mole*:
```shell
pip install .
```
### Development
```shell
# Python virtual environment
python3 -m venv venv/mole_dev
source venv/mole_dev/bin/activate

# Binary Ninja Python API
python $BINJA_BIN/scripts/install_api.py

# Mole
pip install -e .[develop]
```

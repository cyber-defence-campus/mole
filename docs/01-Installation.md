# Installation
In the following, we assume that the variables `$BINJA_BIN` and `$BINJA_USR` point to your *Binary Ninja*'s [binary path](https://docs.binary.ninja/guide/index.html#binary-path) and [user folder](https://docs.binary.ninja/guide/index.html#user-folder), respectively. Use the following steps to install *Mole*:

- Clone the plugin to your *Binary Ninja*'s user folder:
  ```shell
  cd $BINJA_USR/plugins/
  git clone https://github.com/pdamian/mole.git && cd mole/
  ```
- Create and activate a new Python virtual environment for *Mole* (optional, but recommended):
  ```shell
  python3 -m venv venv/mole
  source venv/mole/bin/activate
  ```
- Install *Binary Ninja*'s Python [API](https://docs.binary.ninja/dev/batch.html#install-the-api):
  ```shell
  python $BINJA_BIN/scripts/install_api.py
  ```
- Install *Mole* either in standard or development mode:
  ```shell
  # Standard
  pip install .

  # Development
  pip install -e .[develop]
  pre-commit install
  ```
- Lauch *Binary Ninja* outside the virtual environment:
  ```shell
  $BINJA_BIN/binaryninja &
  ```
----------------------------------------------------------------------------------------------------
[Go-Back](../README.md)
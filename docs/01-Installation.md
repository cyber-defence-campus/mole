# Installation
## Plugin Manager
*Mole* is available through the *Binary Ninja* [Plugin Manager](https://docs.binary.ninja/guide/plugins.html#plugin-manager), which is the easiest way to install it. However, to use *Mole* in headless mode, you will need to follow the manual installation steps described in the next section.
## Manual Installation
In the following, we assume that the variables `$BINJA_BIN` and `$BINJA_USR` point to your *Binary Ninja*'s [binary path](https://docs.binary.ninja/guide/index.html#binary-path) and [user folder](https://docs.binary.ninja/guide/index.html#user-folder), respectively. Use the following steps to install *Mole*:

- Clone the plugin into your *Binary Ninja* user plugins directory:
  ```shell
  cd $BINJA_USR/plugins/
  git clone https://github.com/cyber-defence-campus/mole.git mole-plugin && cd mole-plugin/
  ```
  **WARNING**: Do not name the target directory `mole`.
- Create and activate a new Python virtual environment for *Mole* (optional, but recommended):
  ```shell
  python3 -m venv venv/mole
  source venv/mole/bin/activate
  ```
- Install *Binary Ninja*'s Python [API](https://docs.binary.ninja/dev/batch.html#install-the-api):
  ```shell
  (mole)$ python $BINJA_BIN/scripts/install_api.py
  ```
- Install *Mole* either in standard or development mode:
  ```shell
  # Standard
  (mole)$ pip install .

  # Development
  #   WARNING:
  #   When installed using the -e (editable) flag with pip, Binary Ninja must be launched from
  #   within the activated virtual environment (mole)
  (mole)$ pip install -e .[develop]
  (mole)$ pre-commit install
  (mole)$ $BINJA_BIN/binaryninja &
  ```
- If you are using a virtual environment, consider configuring the corresponding `site-packages` directory in *Binary Ninja*'s settings.
----------------------------------------------------------------------------------------------------
[Back-To-README](../README.md#documentation)
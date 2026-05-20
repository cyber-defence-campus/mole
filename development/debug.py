from binaryninja import execute_on_main_thread
import debugpy
import sys

if sys.platform == "win32":
    debugpy.configure(python="/python", qt="pyside2")
else:
    debugpy.configure(python="/bin/python3", qt="pyside2")
debugpy.listen(("127.0.0.1", 5678))
debugpy.wait_for_client()
execute_on_main_thread(lambda: debugpy.debug_this_thread())

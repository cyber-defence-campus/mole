from __future__                 import annotations
from mole.core.controller       import Controller
from mole.common.log            import Logger

# TODO: handle headless mode here
runs_headless = False

tag = "Mole",
log = Logger(level="debug")

from mole.core.model import SidebarModel
model: SidebarModel = SidebarModel(tag, log).init()
if not runs_headless:
    from mole.core.view import SidebarView
    view = SidebarView(tag, log)
    controller = Controller(view, model, tag, log, runs_headless)
    view.set_controller(controller)
    view.init()
else:
    log.error("Headless mode not yet implemented.")
#self.load_custom_conf_files()
#self.load_main_conf_file()
#return self
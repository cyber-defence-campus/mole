from binaryninja import BinaryView, Function, PluginCommand
from .common.log import Logger


class Plugin:
	"""
	Class to register the plugin with Binary Ninja.
	"""
	
	@staticmethod
	def register() -> None:
		PluginCommand.register(
			"Mole\\Analyze Binary",
			"Search the entire binary for potential vulnerabilities",
			Plugin.analyze_binary)
		PluginCommand.register_for_function(
			"Mole\\Analyze Function",
			"Search the current function for potential vulnerabilities",
			Plugin.analyze_function)
		return
	
	@staticmethod
	def analyze_binary(bv: BinaryView) -> None:
		Logger.debug("Start", "Analyze.Binary")
		Logger.debug("Finished", "Analyze.Binary")
		return

	@staticmethod
	def analyze_function(bv: BinaryView, fun: Function) -> None:
		Logger.debug("Start", "Analyze.Function")
		Logger.debug("Finished", "Analyze.Function")
		return
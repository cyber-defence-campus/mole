from binaryninja import BinaryView, Function, PluginCommand
from .common.log import Logger
from .test       import Sink


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
		Logger.info("Analyze.Binary", "Start")
		sink = Sink(bv, ["memcpy", "__builtin_memcpy"])
		Logger.info("Analyze.Binary", "Finished")
		return

	@staticmethod
	def analyze_function(bv: BinaryView, fun: Function) -> None:
		Logger.info("Analyze.Function", "Start")
		Logger.info("Analyze.Function", "Finished")
		return
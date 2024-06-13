import binaryninja as bn
from .test import LibcMemcpy


class Plugin:
	"""
	Class to register the plugin with Binary Ninja.
	"""
	@staticmethod
	def register() -> None:
		bn.PluginCommand.register(
			"Mole\\Analyze Binary",
			"Search the entire binary for potential vulnerabilities",
			Plugin.analyze_binary)
		return
	
	@staticmethod
	def analyze_binary(bv: bn.BinaryView) -> None:
		LibcMemcpy(bv).find_all()
		return
	

def main() -> None:
	# TODO: Process a binary in headless mode
	return


if __name__ == "__main__":
	main()
import argparse
import binaryninja    as bn
from   .analysis.libc import LibcMemcpy
from   .common.log    import Logger


log = Logger("debug")


class Plugin:
	"""
	This class registers the plugin with Binary Ninja.
	"""

	@staticmethod
	def register(
		) -> None:
		"""
		"""
		bn.PluginCommand.register(
			"Mole\\Analyze Binary",
			"Search the entire binary for potential vulnerabilities",
			Plugin.analyze_binary)
		return
	
	@staticmethod
	def analyze_binary(
		bv: bn.BinaryView
		) -> None:
		"""
		"""
		LibcMemcpy(bv, ["getenv", "__builtin_getenv"], log=log).analyze_all()
		return
	

def main(
	) -> None:
	"""
	This method processes a give binary in headless mode.
	"""
	# Parse arguments
	description = """
	TODO: Provide a description
	"""
	parser = argparse.ArgumentParser(
		description=description,
		formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument(
		"file",
		help="file to analyze")
	parser.add_argument(
		"--log_level",
		choices=["error", "warning", "info", "debug"], default="info",
		help="log level")
	args = parser.parse_args()
	# Create logger
	global log
	log = Logger(args.log_level)
	# Analyze binary
	bv = bn.load(args.file)
	bv.update_analysis_and_wait()
	Plugin.analyze_binary(bv)
	bv.file.close()
	return


if __name__ == "__main__":
	main()
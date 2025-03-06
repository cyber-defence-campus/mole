from   concurrent                 import futures
from   mole.core.data             import Path
from   multiprocessing            import Pipe
from   multiprocessing.connection import Connection
from   typing                     import Dict, List
import binaryninja                as bn
import json                       as json


# MediumLevelILBackwardSlicer
# - slice_backwards -> Tuple[MediumLevelILInstructionGraph.to_dict(), MediumLevelILFunctionGraph.to_dict()]


class Function:
    """
    TODO: Rename class
    """

    def do_terminate(
        conn: Connection,
    ) -> bool:
        """
        """
        if conn.poll():
            msg = conn.recv()
            return msg == "TERMINATE"
        return False


class SourceFunction(Function):
    """
    TODO: Rename class
    """

    @staticmethod
    def find(
        conn: Connection,
        filename: str,
        source_name: str,
        max_call_level: int = 0
    ) -> None:
        """
        """
        # TODO: source = ConfigManager.get_source(source_name)

        with bn.load(filename) as bv:
            bv.update_analysis_and_wait()
            raise Exception("Test exception")

        return


class SinkFunction(Function):
    """
    TODO: Rename class
    """

    @staticmethod
    def find(
        conn: Connection,
        filename: str,
        sink_name: str,
        source_names: List[str],
        max_call_level: int = None,
        max_slice_depth: int = None
    ) -> None:
        """
        """
        # TODO: sources = ConfigManager.get_all_sources()
        # TODO: sink = ConfigManager.get_sink(sink_name)

        # Simulated path
        with bn.load(filename) as bv:
            bv.update_analysis_and_wait()
            path: Path = Path.from_dict(bv, {
                "src_sym_addr": "0x106cc",
                "src_sym_name": "getenv",
                "snk_sym_addr": "0x10700",
                "snk_sym_name": "system",
                "snk_par_idx": 0,
                "src_inst_idx": 11,
                "insts": [
                    [
                        "0x10700",
                        7
                    ]
                ],
                "call_graph": {
                    "tag": "Mole] [system",
                    "log_level": "debug",
                    "nodes": [],
                    "edges": [],
                },
                "comment": "",
                "sha1": "9289a46cb4de520ee900c3057d95bdbbca63406b"
            })
            path.snk_sym_name = sink_name

        import random, time

        time.sleep(random.uniform(0, 5))
        if Function.do_terminate(conn): return
        conn.send(("sink", json.dumps(path.to_dict())))

        time.sleep(random.uniform(0, 5))
        if Function.do_terminate(conn): return
        conn.send(("sink", json.dumps(path.to_dict())))

        return


if __name__ == "__main__":
    filename = "./test/bin/function_calling-02.linux-armv7"
    source_names = ["getenv"]
    sink_names = ["memcpy", "system"]
    max_workers = 2

    print("Start analysis")

    # NOTE: In the parent process, we can only load the BinaryView after all child process have
    # been spawned.
    
    with futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        parent_conn, child_conn = Pipe()
        tasks_cnt = 0; tasks_total_cnt = len(source_names) + len(sink_names)
        tasks: Dict[futures.Future, str] = {}

        # Submit source slicing tasks to subprocesses
        for source_name in source_names:
            tasks_cnt += 1
            progress = f"[{tasks_cnt:d}/{tasks_total_cnt:d}]"
            print(f"{progress:s} Start slicing source '{source_name:s}'")
            task = executor.submit(
                SourceFunction.find,
                child_conn,
                filename,
                source_name
            )
            tasks[task] = ("source", source_name)
        
        # Submit sink slicing tasks to subprocesses
        for sink_name in sink_names:
            tasks_cnt += 1
            progress = f"[{tasks_cnt:d}/{tasks_total_cnt:d}]"
            print(f"{progress:s} Start slicing sink '{sink_name:s}'")
            task = executor.submit(
                SinkFunction.find,
                child_conn,
                filename,
                sink_name,
                []
            )
            tasks[task] = ("sink", sink_name)

        # Process subprocesses results
        with bn.load(filename) as bv:
            bv.update_analysis_and_wait()
            found_paths = 0
            while any(not task.done() for task in tasks):
                while parent_conn.poll():
                    type: str; msg: str
                    type, msg = parent_conn.recv()
                    # Handle result of slicing a source
                    if type == "source":
                        pass
                    # Handle result of slicing a sink
                    elif type == "sink":
                        path = Path.from_dict(bv, json.loads(msg))
                        found_paths += 1
                        print(f"Found new path #{found_paths:d}: '{str(path):s}'")
                # NOTE: Test subprocess termination
                if found_paths > 2:
                    parent_conn.send("TERMINATE")
                    break
        # Process subprocesses return values
        tasks_cnt = 0
        for task in futures.as_completed(tasks):
            tasks_cnt += 1
            type, name = tasks[task]
            progress = f"[{tasks_cnt:d}/{tasks_total_cnt:d}]"
            try:
                task.result()
            except Exception as e:
                print(f"{progress:s} Error while slicing {type:s} '{name:s}': {str(e):s}")
            print(f"{progress:s} Finished slicing {type:s} '{name:s}'")
    
    print("Analysis finished")
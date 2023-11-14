# builtin imports
import hashlib
import logging
import os
import stat
import threading
import time

from pathlib import Path
from typing import List, Union

# Third party imports
from libpastis import ClientAgent, BinaryPackage
from libpastis.types import CheckMode, CoverageMode, ExecMode, FuzzingEngineInfo, SeedInjectLoc, SeedType, State, \
                            LogLevel, AlertData, FuzzMode

# Local imports
import pastissydr
from pastissydr.sydr import SydrProcess
from pastissydr.workspace import Workspace


# Inotify logs are very talkative, set them to ERROR
for logger in (logging.getLogger(x) for x in ["watchdog.observers.inotify_buffer", 'watchdog.observers', "watchdog"]):
    logger.setLevel(logging.ERROR)


logger = logging.getLogger("pastis_sydr_logger")


class SydrDriver:

    def __init__(self, agent: ClientAgent, telemetry_frequency: int = 30):
        # Internal objects
        self._agent = agent
        self.workspace = Workspace()
        self.sydr = SydrProcess()

        # Register callbacks.
        self._agent.register_seed_callback(self.__seed_received)
        self._agent.register_stop_callback(self.__stop_received)

        # Configure hookds on workspace
        self.workspace.add_creation_hook(self.workspace.corpus_dir, self.__send_seed)
        self.workspace.add_creation_hook(self.workspace.sydr_dir, self.__send_seed)
        self.workspace.add_creation_hook(self.workspace.crash_dir, self.__send_crash)
        self.workspace.add_file_modification_hook(self.workspace.stats_dir, self.__send_telemetry)

        self._started = False

        # Telemetry frequency
        self._tel_frequency = telemetry_frequency
        self._tel_last = time.time()

        # Runtime data
        self._tot_seeds = 0
        self._seed_recvs = set()  # Seed received to make sure NOT to send them back
        self._already_sent = set() # Sent seeds


    @staticmethod
    def hash_seed(seed: bytes):
        return hashlib.md5(seed).hexdigest()


    @property
    def started(self):
        return self._started


    def start(self, package: BinaryPackage, argv: List[str], fuzz_mode: FuzzMode, input_source: SeedInjectLoc, engine_args: str):
        self.workspace.start()  # Start looking at directories

        # Unpack different targets
        fuzz_target = str(package.executable_path.absolute())
        sydr_target = ""
        cmplog_target = str(package.cmplog.absolute()) if package.cmplog else None
        dictionary = ""
        if fuzz_mode == FuzzMode.BINARY_ONLY:
            logger.info("Fuzzing mode BINARY_ONLY detected. Use same target for Sydr-Fuzz and AFL++")
            sydr_target = fuzz_target
            if len(package.other_files) > 0:
                logger.info(f"Received other files in BinaryBackage: {package.other_files}")
                for extra_file in package.other_files:
                    if extra_file.name.endswith(".dict"):
                        dictionary = str(extra_file.absolute())
                        logger.info(f"Received a dictionary file: {dictionary}")
        else:
            logger.warning("Fuzzing mode INSTRUMENTED detected. Sydr-Fuzz required separate uninstrumented target binary")
            if len(package.other_files) == 0:
                raise FileNotFoundError(f"Can't find uninstrumented target for Sydr-Fuzz in package")
            for extra_file in package.other_files:
                if extra_file.name.endswith(".dict"):
                    dictionary = str(extra_file.absolute())
                    logger.info(f"Received a dictionary file: {dictionary}")
                    continue
                sydr_target = extra_file.absolute()
                logger.warning(f"Uninstrumented binary target for Sydr-Fuzz is {sydr_target}")
                sydr_target.chmod(stat.S_IRWXU)
                sydr_target = str(sydr_target)
            if sydr_target == "":
                raise FileNotFoundError(f"Can't find uninstrumented target for Sydr-Fuzz in package")

        logger.info(f"Start Sydr process, extra engine_args:{engine_args}")
        self.sydr.start(fuzz_target,
                        sydr_target,
                        " ".join(argv),
                        self.workspace,
                        fuzz_mode,
                        input_source == SeedInjectLoc.STDIN,
                        engine_args,
                        dictionary,
                        cmplog_target)
        self._started = True

    def start_received(self, fname: str, binary: bytes, engine: FuzzingEngineInfo, _exec_mode: ExecMode, fuzz_mode: FuzzMode, _check_mode: CheckMode,
                       _cov_mode: CoverageMode, input_source: SeedInjectLoc, engine_args: str, argv: List[str], _kl_report: str = None):
        logger.info(f"[START] bin:{fname} engine:{engine.name} seedloc:{input_source.name}")
        if self.started:
            self._agent.send_log(LogLevel.CRITICAL, "Instance already started!")
            return

        if engine.name != "SYDR":
            logger.error(f"Wrong fuzzing engine received {engine.name} while I am Sydr")
            self._agent.send_log(LogLevel.ERROR, f"Invalid fuzzing engine received {engine.name} can't do anything")
            return
        if engine.version != pastissydr.__version__:
            logger.error(f"Wrong fuzzing engine version {engine.version} received")
            self._agent.send_log(LogLevel.ERROR, f"Invalid fuzzing engine version {engine.version} do nothing")
            return

        # Retrieve package out of the binary received
        try:
            package = BinaryPackage.from_binary(fname, binary, self.workspace.target_dir)
        except FileNotFoundError:
            logger.error("Invalid package received: FileNotFound")
            self._agent.send_log(LogLevel.ERROR, "Invalid package provided: FileNotFound")
            return
        except ValueError:
            logger.error("Invalid package received: ValueError")
            self._agent.send_log(LogLevel.ERROR, "Invalid package provided: ValueError")
            return

        # Start fuzzer.
        self.start(package, argv, fuzz_mode, input_source, engine_args)


    def init_agent(self, remote: str = "localhost", port: int = 5555):
        self._agent.register_start_callback(self.start_received)  # Register start because launched manually (not by pastisd)
        self._agent.connect(remote, port)
        self._agent.start()
        # Send initial HELLO message, whick will make the Broker send the START message.
        self._agent.send_hello([FuzzingEngineInfo("SYDR", pastissydr.__version__, "sydrbroker")])


    def stop(self):
        self.sydr.stop()
        self.workspace.stop()
        self._started = False
        # Wait for copying Sydr inputs
        if not os.path.isfile(self.workspace.output_dir / "sydr-fuzz.log"):
            return
        with open(self.workspace.output_dir / "sydr-fuzz.log") as f:
            lines = f.readlines()
            lines.reverse()
            for line in lines:
                if "Keeping input" in line:
                    name = line.split(' ')[-1].strip().strip('\"')
                    self.__send_seed(self.workspace.sydr_dir / name)
                elif "Received SIGINT/SIGTERM: terminating" in line:
                    break


    def add_seed(self, seed: bytes):
        remote_seed_id = str(len(self._seed_recvs)).zfill(6)
        seed_path = self.workspace.dynamic_input_dir / f"id:{remote_seed_id},seed-{hashlib.md5(seed).hexdigest()}"
        seed_path.write_bytes(seed)


    def add_initial_seed(self, file: Union[str, Path]):
        p = Path(file)
        logger.info(f"add initial seed {file.name}")
        # Write seed to disk.
        seed_path = self.workspace.input_dir / p.name
        seed_path.write_bytes(p.read_bytes())


    def run(self):
        self.sydr.wait()        


    def __seed_received(self, typ: SeedType, seed: bytes):
        h = self.hash_seed(seed)
        logger.info(f"[SEED] received {h} ({typ.name})")
        self.add_seed(seed)
        self._seed_recvs.add(h)


    def __stop_received(self):
        logger.info(f"[STOP] received")
        self.stop()


    def __send_seed(self, filename: Path):
        self.__send(filename, SeedType.INPUT)


    def __send_crash(self, filename: Path):
        # Skip README file that AFL adds to the crash folder.
        if filename.name != 'README.txt':
            self.__send(filename, SeedType.CRASH)


    def __send(self, filename: Path, typ: SeedType):
        file = Path(filename)
        raw = file.read_bytes()
        h = self.hash_seed(raw)
        if h in self._already_sent:
            #logger.debug(f'[{typ.name}] Seed was already sent: {filename}, do not send it back')
            return
        self._tot_seeds += 1
        logger.debug(f'[{typ.name}] Sending new: {h} [{self._tot_seeds}]')
        if h not in self._seed_recvs:
            self._agent.send_seed(typ, raw)
            self._already_sent.add(h)
        else:
            logger.info("seed (previously sent) do not send it back")


    def __send_telemetry(self, filename: Path):
        if filename.name != SydrProcess.STAT_FILE:
            return

        now = time.time()
        if now < (self._tel_last + self._tel_frequency):
            return
        self._tel_last = now

        logger.debug(f'[TELEMETRY] Stats file updated: {filename}')

        with open(filename, 'r') as stats_file:
            try:
                stats = {}
                for line in stats_file.readlines():
                    k, v = line.strip('\n').split(':')
                    stats[k.strip()] = v.strip()

                state = State.RUNNING
                last_cov_update = int(stats['last_update'])
                total_exec = int(stats['execs_done'])
                exec_per_sec = int(float(stats['execs_per_sec']))
                timeout = int(stats['unique_hangs']) if 'unique_hangs' in stats else None # N/A in AFL-QEMU.
                coverage_edge = int(stats['total_edges'])
                cycle = int(stats['cycles_done'])
                coverage_path = int(stats['paths_total']) if 'paths_total' in stats else None # N/A in AFL-QEMU.

                # NOTE: `coverage_block` does not apply for AFLPP.
                self._agent.send_telemetry(state=state,
                                           exec_per_sec=exec_per_sec,
                                           total_exec=total_exec,
                                           cycle=cycle,
                                           timeout=timeout,
                                           coverage_edge=coverage_edge,
                                           coverage_path=coverage_path,
                                           last_cov_update=last_cov_update)
            except:
                logger.error(f'Error retrieving stats!')

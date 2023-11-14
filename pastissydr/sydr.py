# builtin imports
import logging
import os
import re
import signal
import subprocess
import time
from typing import Optional, Union
from pathlib import Path

# third-party imports
import shutil
import toml
from libpastis.types import FuzzMode

# Local imports
from .workspace import Workspace

logger = logging.getLogger("pastis_sydr_logger")

class SydrProcess:

    SYDR_ENV_VAR = "SYDR_PATH"
    SYDR_BINARY = "/fuzz/sydr/sydr-fuzz"
    STAT_FILE = "fuzzer_stats"

    def __init__(self, path: str = None):
        self.__path = self.find_sydr_binary(path)
        if self.__path is None:
            raise FileNotFoundError(f"Can't find Sydr-Fuzz binary, default location: {SydrProcess.SYDR_BINARY}")

        self.__process = None
        self.__log_file = None

    @staticmethod
    def find_sydr_binary(root_dir: Union[Path, str]) -> Optional[Path]:
        # First, check environment variable.
        bin_path = os.environ.get(SydrProcess.SYDR_ENV_VAR)
        if bin_path is not None:
            if os.path.isfile(bin_path):
                return bin_path
            bin_path = os.path.join(bin_path, "sydr-fuzz")
            if os.path.isfile(bin_path):
                return bin_path
        
        # Second, try default location.
        bin_path = SydrProcess.SYDR_BINARY if os.path.isfile(SydrProcess.SYDR_BINARY) else None
        if bin_path is not None:
            return bin_path

        return None

    def start(self, fuzztarget: str, sydrtarget: str, target_arguments: str, workspace: Workspace, fuzzmode: FuzzMode, stdin: bool, engine_args: str, dictionary: str, cmplog: Optional[str] = None):
        sydr_out = str(workspace.output_dir)
        config_file = os.path.join(workspace.root_dir, 'sydr-fuzz.toml')
        self.__log_file = workspace.output_dir / "sydr-fuzz.log"

        # Build AFL++ arguments.
        afl_args = "-Q " if fuzzmode == FuzzMode.BINARY_ONLY else ""
        afl_args += f"-t 1000+ -m none -i {workspace.input_dir}"
        if dictionary != "":
            afl_args += f" -x {dictionary}"
        if engine_args != "":
            logger.info(f"Received extra engine arguments from broker: {engine_args}")
            logger.warning(f"IGNORING ARGUMENTS {engine_args}")
            #afl_args += " " + engine_args

        # Construct toml.
        sydr_args = "-s 60 -m 8192 --wait-jobs 300"
        if "@@" in target_arguments:
            sydr_cmd = f"{sydrtarget} {target_arguments}"
            fuzz_cmd = f"{fuzztarget} {target_arguments}"
        else:
            sydr_cmd = f"{sydrtarget} {target_arguments} @@"
            fuzz_cmd = f"{fuzztarget} {target_arguments} @@"
        if stdin:
            sydr_args += " --sym-stdin"
            sydr_cmd = f"{sydrtarget} {target_arguments}"
            fuzz_cmd = f"{fuzztarget} {target_arguments} 2147483647"
        config = {}
        config["sleep-time"] = 10
        config["sydr"] = {}
        config["sydr"]["target"] = sydr_cmd
        config["sydr"]["args"] = (sydr_args)
        config["sydr"]["timeout"] = 180
        config["aflplusplus"] = {}
        config["aflplusplus"]["target"] = fuzz_cmd
        config["aflplusplus"]["args"] = afl_args
        config["aflplusplus"]["cmin"] = False

        config_str = toml.dumps(config)
        print('[sydr-fuzz] Config: ' + config_str)
        text_file = open(config_file, "wt")
        text_file.write(config_str)
        text_file.close()
        
        # Setup basic AFL++ environment preferences.
        os.environ["AFL_NO_UI"] = "1"
        os.environ["AFL_IMPORT_FIRST"] = "1"
        os.environ["AFL_SKIP_CPUFREQ"] = "1"
        os.environ["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        os.environ['AFL_DISABLE_TRIM'] = "1"
        os.environ['AFL_FAST_CAL'] = "1"
        os.environ['AFL_IGNORE_UNKNOWN_ENVS'] = "1"
        os.environ['AFL_CMPLOG_ONLY_NEW'] = "1"
        
        # Build Sydr-Fuzz cmdline.
        command = [
            self.__path,
            '-c',
            config_file,
            '-l',
            'trace',
            '-o',
            sydr_out,
            'run',
        ]

        logger.info(f"Run Sydr-Fuzz: {command}")
        logger.debug(f"Workspace: {workspace.root_dir}")

        # Create a new fuzzer process and set it apart into a new process group.
        self.__process = subprocess.Popen(command, cwd=str(workspace.root_dir), preexec_fn=os.setsid)

        logger.debug(f'Process pid: {self.__process.pid}')


    @property
    def instanciated(self):
        return self.__process is not None

    def stop(self):
        if self.__process:
            os.killpg(os.getpgid(self.__process.pid), signal.SIGINT)
            while self.instanciated:
                time.sleep(1)
                with open(self.__log_file) as f:
                    if "[RESULTS]" in f.readlines()[-1]:
                        break
                logger.debug("Wait for sydr-fuzz to stop...")
        else:
            logger.debug(f"Sydr-Fuzz process seems already killed")

    def wait(self):
        while not self.instanciated:
            time.sleep(0.1)
        self.__process.wait()
        logger.info(f"Sydr-Fuzz terminated with code : {self.__process.returncode}")

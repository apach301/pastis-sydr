# builtin imports
from typing import Callable
import time
import tempfile
import os
import logging
from pathlib import Path
from hashlib import md5

# third-party imports
import shutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserverVFS

logger = logging.getLogger("pastis_sydr_logger")

class Workspace(FileSystemEventHandler):

    SYDR_WS_ENV_VAR = "SYDR_WS"
    DEFAULT_WS_PATH = "sydr_workspace"
    STATS_FILE = "fuzzer_stats"

    def __init__(self):
        self.observer = PollingObserverVFS(stat=os.stat, listdir=os.scandir, polling_interval=1)
        self.modif_callbacks = {}  # Map fullpath -> callback
        self.created_callbacks = {}
        self.root_dir = None
        self._setup_workspace()

    def _setup_workspace(self):
        ws = os.environ.get(self.SYDR_WS_ENV_VAR, None)
        if ws is None:
            self.root_dir = (Path(tempfile.gettempdir()) / self.DEFAULT_WS_PATH) / str(time.time()).replace(".", "")
        else:
            self.root_dir = Path(ws)  # Use the one provided

        if os.path.exists(self.root_dir):
            logger.warning(f"Remove existing workspace {self.root_dir}")
            shutil.rmtree(self.root_dir)

        for d in [self.target_dir, self.input_dir, self.dynamic_input_dir, self.corpus_dir, self.sydr_dir, self.crash_dir]:
            d.mkdir(parents=True)

        # Create dummy input file.
        # AFLPP requires that the initial seed directory is not empty.
        # TODO Is there a better approach to this?
        seed_path = self.input_dir / 'seed-dummy'
        seed_path.write_bytes(b'A')

    @property
    def target_dir(self):
        return self.root_dir / 'target'

    @property
    def input_dir(self):
        return self.root_dir / 'inputs' / 'initial'

    @property
    def output_dir(self):
        return self.root_dir / 'sydr-fuzz-output'

    @property
    def dynamic_input_dir(self):
        return self.output_dir / 'aflplusplus' / 'remote-worker' / 'queue'

    @property
    def corpus_dir(self):
        return self.output_dir / 'aflplusplus' / 'afl_main-worker' / 'queue'

    @property
    def sydr_dir(self):
        return self.output_dir / 'aflplusplus' / 'sydr-worker' / 'queue'

    @property
    def crash_dir(self):
        return self.output_dir / 'crashes'

    @property
    def stats_dir(self):
        return self.output_dir / 'aflplusplus' / 'afl_main-worker'

    @property
    def stats_file(self):
        return self.stats_dir / self.STATS_FILE

    def on_modified(self, event):
        path = Path(event.src_path)
        if path.is_dir():
            return  # We don't care about directories
        if path.parent in self.modif_callbacks:
            self.modif_callbacks[path.parent](path)  # call the callback
        else:
            pass  # Do nothing at the moment

    def on_created(self, event):
        path = Path(event.src_path)
        if path.is_dir():
            return  # We don't care about directories
        if path.parent in self.created_callbacks:
            self.created_callbacks[path.parent](path)  # call the callback
        else:
            pass  # Do nothing at the moment

    def add_file_modification_hook(self, path: str, callback: Callable):
        self.observer.schedule(self, path=path, recursive=True)
        self.modif_callbacks[path] = callback

    def add_creation_hook(self, path: str, callback: Callable):
        self.observer.schedule(self, path=path, recursive=True)
        self.created_callbacks[path] = callback

    def start(self):
        self.observer.start()

    def stop(self):
        self.observer.stop()

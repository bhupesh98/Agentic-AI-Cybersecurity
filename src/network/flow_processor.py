"""Async flow processor with worker pool."""

import threading
import queue
from typing import Callable


class FlowProcessor:
    def __init__(self, process_func: Callable, num_workers: int = 4):
        self.process_func = process_func
        self.flow_queue = queue.Queue(maxsize=1000)
        self.workers = []
        self.is_running = False
        self.num_workers = num_workers
        
    def start(self):
        self.is_running = True
        for i in range(self.num_workers):
            worker = threading.Thread(target=self._worker_loop, daemon=True)
            worker.start()
            self.workers.append(worker)
    
    def stop(self):
        self.is_running = False
        self.flow_queue.join()
    
    def submit_flow(self, flow):
        try:
            self.flow_queue.put(flow, timeout=1.0)
        except queue.Full:
            print("⚠️  Queue full, dropping flow")
    
    def _worker_loop(self):
        while self.is_running:
            try:
                flow = self.flow_queue.get(timeout=0.5)
                self.process_func(flow)
                self.flow_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Worker error: {e}")
                self.flow_queue.task_done()


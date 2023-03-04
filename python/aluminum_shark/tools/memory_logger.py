"""
Run the passed commmand and record the memory uusage and run time
"""

import psutil, sys, time, os
from subprocess import Popen
from threading import Thread, Event
from queue import Queue


def task(stop_event: Event, pid: int, queue: Queue, history=False):
  vms = 0
  rss = 0
  if history:
    rss_history = []
    vms_history = []
  while True:
    time.sleep(1)
    try:
      pmem = psutil.Process(pid).memory_info()
    except:
      break
    vms = max(pmem.vms, vms)
    rss = max(pmem.rss, rss)
    if history:
      rss_history.append(pmem.rss)
      vms_history.append(pmem.vms)
    if stop_event.is_set():
      break
  if history:
    queue.put({
        'vms': vms,
        'rss': rss,
        'vms_history': vms_history,
        'rss_history': rss_history
    })
  else:
    queue.put({'vms': vms, 'rss': rss})


class MemoryLogger(object):

  factors = {'byte': 1, 'kb': 1024, 'mb': 1024 * 1024, 'gb': 1024 * 1024 * 1024}

  def __init__(self, pid=None, log_history=False) -> None:
    if pid is None:
      self.pid = os.getpid()
    else:
      self.pid = pid
    self.event = Event()
    self.queue = Queue()
    self.log_history = log_history

  def start(self):
    self.thread = Thread(target=task,
                         args=(self.event, self.pid, self.queue,
                               self.log_history),
                         name='memlogger')
    self.thread.start()

  def stop(self):
    self.event.set()
    if self.thread.isAlive():
      self.thread.join()

  def format(self, unit):
    factor = self.factors[unit]
    result = {}
    for key in self.result:
      value = self.result[key]
      if isinstance(value, int):
        value = value / factor
      if isinstance(value, list) and len(value) > 0 and isinstance(
          value[0], int):
        value = [x / factor for x in value]
      result[key] = value
    result['unit'] = unit
    return result

  def stop_and_read(self, unit='byte'):
    self.stop()
    self.result = self.queue.get()
    return self.format(unit)


if __name__ == '__main__':
  start = time.time()
  args = sys.argv[1:]
  print(args)

  proc = Popen(args)
  pid = proc.pid

  logger = MemoryLogger(pid=pid)
  logger.start()
  returncode = proc.wait()
  result = logger.stop_and_read(unit='mb')

  print('#########################')
  if (returncode != 0):
    print(f'{sys.arv[1]} did not exit cleanly. exit code: {returncode}')
  print('max vms:', result['vms'], 'MB')
  print('max rss:', result['rss'], 'MB')
  print('run time:', time.time() - start)
  exit(returncode)

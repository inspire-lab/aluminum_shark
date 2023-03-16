"""
Run the passed commmand and record the memory uusage and run time
"""

import psutil, sys, time, os
from subprocess import Popen, PIPE
from threading import Thread, Event
from queue import Queue
import fileinput
import json


def task(stop_event: Event,
         pid: int,
         queue: Queue,
         interval: float,
         history=False,
         to_file=False):
  vms = 0
  rss = 0
  print(f'started memory logging. logging every {interval}s')
  if history or to_file:
    rss_history = []
    vms_history = []

  def read():
    nonlocal vms, rss, rss_history, vms_history
    print('reading memory')
    pmem = psutil.Process(pid).memory_info()

    vms = max(pmem.vms, vms)
    rss = max(pmem.rss, rss)
    if history or to_file:
      rss_history.append(pmem.rss)
      vms_history.append(pmem.vms)
    return stop_event.is_set()

  if to_file:
    start = time.time()
    # construct a cool filename
    filename = f'shark_memlogger_{start}.log'
    # write every line `buffering=1`
    with open(filename, 'w', buffering=1) as f:
      while read():
        f.write(
            f'time:{time.time()-start}:, rss:{rss_history[-1]}, vms:{vms_history[-1]}\n'
        )
        time.sleep(interval)
  else:
    while read():
      time.sleep(interval)

  if history:
    queue.put({
        'vms': vms,
        'rss': rss,
        'vms_history': vms_history,
        'rss_history': rss_history
    })
  else:
    queue.put({'vms': vms, 'rss': rss})


class MemoryLoggerThread(object):

  factors = {'byte': 1, 'kb': 1024, 'mb': 1024 * 1024, 'gb': 1024 * 1024 * 1024}

  def __init__(self,
               pid=None,
               interval: float = 1,
               log_history=False,
               to_file=False) -> None:
    if pid is None:
      self.pid = os.getpid()
    else:
      self.pid = pid
    self.event = Event()
    self.queue = Queue()
    self.log_history = log_history
    self.interval = interval
    self.to_file = to_file

  def start(self):
    self.thread = Thread(target=task,
                         args=(self.event, self.pid, self.queue, self.interval,
                               self.log_history, self.to_file),
                         daemon=True,
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


# Subprocesss based logger

# a few globals

interupt_code = 'stop'
internal_tag = '__internal__'


class MemoryLogger(object):

  factors = {'byte': 1, 'kb': 1024, 'mb': 1024 * 1024, 'gb': 1024 * 1024 * 1024}

  def __init__(self,
               pid=None,
               interval: float = 1,
               log_history=False,
               to_file=False) -> None:
    if pid is None:
      self.pid = os.getpid()
    else:
      self.pid = pid
    self.event = Event()
    self.queue = Queue()
    self.log_history = log_history
    self.interval = interval
    self.to_file = to_file
    self.process = None

  def start(self):
    # build the arguments for popen
    args = [
        sys.executable, __file__, internal_tag,
        str(self.pid),
        str(self.interval),
        str(int(self.log_history)),
        str(int(self.to_file))
    ]
    print('starting memory logger:', ' '.join(args))
    self.process = Popen(
        args,
        stdin=PIPE,
        stdout=PIPE,
        #  stderr=PIPE,
        text=True,
        cwd=os.getcwd())

  def stop(self):
    if self.process is None:
      return
    # send stop message
    try:
      process_out, process_err = self.process.communicate(input=interupt_code)
      # read subprocess stdout
      print(f'subprocess result: {process_out} {process_err}')
      print(f'{type(process_out)}, {process_out}')
      self.result = json.loads(process_out)
    except Exception as e:
      print('stopping memory logger messed up. reason: ', e)
      self.result = {
          'vms': -1,
          'rss': -1,
          'vms_history': [-1],
          'rss_history': [-1]
      }
    self.process = None

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
    return self.format(unit)


def process_task(pid: int, interval: float, history=False, to_file=False):
  vms = 0
  rss = 0
  rss_history = []
  vms_history = []
  # set stdin to nonblocking
  os.set_blocking(sys.stdin.fileno(), False)

  def read():
    nonlocal vms, rss, rss_history, vms_history
    pmem = psutil.Process(pid).memory_info()

    vms = max(pmem.vms, vms)
    rss = max(pmem.rss, rss)
    if history or to_file:
      rss_history.append(pmem.rss)
      vms_history.append(pmem.vms)
    # check if we need to stop

    return sys.stdin.readline() == ''

  if to_file:
    start = time.time()
    # construct a cool filename
    filename = f'shark_memlogger_{start}.log'
    # write every line `buffering=1`
    with open(filename, 'w', buffering=1) as f:
      while read():
        f.write(
            f'time:{time.time()-start}:, rss:{rss_history[-1]}, vms:{vms_history[-1]}\n'
        )
        time.sleep(interval)
  else:
    while read():
      time.sleep(interval)
      pass

  # write result to stdout
  if history:
    print(
        json.dumps({
            'vms': vms,
            'rss': rss,
            'vms_history': vms_history,
            'rss_history': rss_history
        }))
  else:
    print(json.dumps({'vms': vms, 'rss': rss}))


def main():

  # command comming in here follow this patter:
  # python $PATH_TO/memory_logger.py __internal__ pid itnerval log_history to_file
  pid = int(sys.argv[2])
  interval = float(sys.argv[3])
  log_history = int(sys.argv[4]) != 0
  to_file = int(sys.argv[5]) != 0
  sys.argv = []
  process_task(pid, interval, log_history, to_file)


if __name__ == '__main__':
  if len(sys.argv) > 1 and sys.argv[1] == internal_tag:
    main()
    exit(0)

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

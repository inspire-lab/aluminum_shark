"""
Run the passed commmand and record the memory uusage and run time
"""

import psutil, sys, time
from subprocess import Popen

start = time.time()
args = sys.argv[1:]
print(args)
proc = Popen(args)

pid = proc.pid
vms = 0
rss = 0

while proc.poll() is None:
  pmem = psutil.Process(pid).memory_info()
  vms = max(pmem.vms, vms)
  rss = max(pmem.rss, rss)
  time.sleep(.01)

print('#########################')
if (proc.returncode != 0):
  print(f'{sys.arv[1]} did not exit cleanly. exit code: {proc.returncode}')
print('max vms:', vms / (1024 * 1024), 'MB')
print('max rss:', rss / (1024 * 1024), 'MB')
print('run time:', time.time() - start)

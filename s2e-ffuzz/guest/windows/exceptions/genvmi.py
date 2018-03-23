
import os
import jinja2
import argparse
import pickle
import shlex
import tempfile
import shutil
import threading
import time
import sys
import signal
import subprocess

IDA = '/opt/ida-6.8/idaq64'
MAX_THREADS = 30
LOG = "scan.log"

jinja_environment = jinja2.Environment(trim_blocks = True,
        loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), '.')))

def filter_hex(value):
    try:
        return "%#x" % (value)
    except:
        return value

jinja_environment.filters['hex'] = filter_hex


def read_file_list(filename):
    modules = []
    with open(filename) as f:
        modules = [fn.strip('\n') for fn in f.readlines()]
    return modules

def scan(work_dir, ida_script, filename, dump_file):

    base_name = os.path.basename(filename)
    work_file = os.path.join(work_dir, base_name)
    shutil.copyfile(filename, work_file)

    cmdline = '{0} -B -S"{1} -f {2} -o {3}" {2}'.format(
               IDA, ida_script, work_file, dump_file, work_file
            )

    print("Scanning {}".format(filename))
    print(cmdline)
    args = shlex.split(cmdline)
    try:
        subprocess.check_call(args)
        with open(LOG, 'a') as log, \
            open(os.path.join(work_dir, 'idaout.txt'), 'r') as f:
            log.write(f.read())
    except:
        print("ERROR: script failed: {}".format(cmdline))

def thread_func(*args):
    (tid, work_dir, ida_script, filename) = args

    dump_file = os.path.join(work_dir, 'vmi.pyh-' + str(tid))
    if os.path.isfile(dump_file):
        os.remove(dump_file)

    scan(work_dir, ida_script, filename, dump_file)

    if not os.path.isfile(dump_file):
        print("No file found after analysis, continue")
        return

    fp = open(dump_file, "rb")
    mod = pickle.load(fp)

    update_data(mod)

    print("Thread {} finished".format(str(tid)))

def update_data(module):
    global data
    global data_lock

    with data_lock:
        print("Updating data")
        for m in data:
            if m['checksum'] == module['checksum']:
                print("Ignoring duplicate with checksum {}".format(module['checksum']))
                return

        data += [module]
        print(module['checksum'])

def render_data(data):
    ret = template.render({'data': data})
    f = open(args.output, 'wt')
    f.write(ret)
    f.close()

def signal_handler(*args):
    global data
    global active_threads
    global temp_dirs

    print("Interrupted, saving data")
    render_data(data)

    for t in active_threads:
        t.join()
        shutil.rmtree(temp_dirs[t])

    sys.exit(0)


template = jinja_environment.get_template('genvmi.tpl')

parser = argparse.ArgumentParser(description='Analyze file.')
parser.add_argument('-d', '--dir', dest="directory", required=True,
                    help="Directory where to search for modules")
parser.add_argument('-m', '--modules', dest="modules", required=True,
                    help="File containing list of modules to scan")
parser.add_argument('-o', '--out', dest="output",
                    help="Output vmi.lua file", default="vmi.lua")
parser.add_argument('-p', '--print', dest="display",
                    help="Print an existing result", default=None)


args = parser.parse_args()

if args.display is not None:
    fp = open(args.display, "rb")
    mod = pickle.load(fp)
    data = [mod]
    ret = template.render({'data': data})
    print(ret)
    sys.exit(0)


file_list = read_file_list(args.modules)

print("{} files in the module list".format(str(len(file_list))))

data = []
data_lock = threading.Lock()


ida_script = os.path.join(os.getcwd(), 'find-stubs.py')
print("Using IDA script {}".format(ida_script))

dump_file = 'vmi.pyh'

active_threads = []
tid = 1

temp_dirs = {}

signal.signal(signal.SIGINT, signal_handler)

for root, dirs, files in os.walk(args.directory):
    dirs.sort()
    files.sort()

    if root == '.':
        root = ''

    for f in files:
        fp = os.path.join(root, f)
        if f in file_list:

            if 'winsxs' in fp or 'patchcache' in fp:
                continue

            while len(active_threads) >= MAX_THREADS:
                print("Too many threads running...")
                for t in active_threads:
                    if not t.isAlive():
                        shutil.rmtree(temp_dirs[t])
                        active_threads.remove(t)

                time.sleep(1)

            work_dir = tempfile.mkdtemp()
            print("Work directory: {}".format(work_dir))

            t = threading.Thread(target=thread_func, args=(tid, work_dir, ida_script, fp))
            print("Starting scan thread {}".format(tid))
            temp_dirs[t] = work_dir
            t.start()
            tid += 1
            with data_lock:
                active_threads += [t]


print("Waiting for threads to finish")
while len(active_threads) > 0:
    for t in active_threads:
        t.join()
        shutil.rmtree(temp_dirs[t])
        active_threads.remove(t)

render_data(data)

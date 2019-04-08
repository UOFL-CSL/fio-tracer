# Copyright (c) 2019, UofL Computer Systems Lab.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without event the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


from collections import OrderedDict
from functools import wraps
from getopt import getopt, GetoptError
from time import strftime, localtime

import configparser
import json
import logging
import platform
import os
import re
import shlex
import signal
import subprocess
import sys
import time


__author__ = 'Jared Gillespie'
__version__ = '0.1.0'


def try_split(s: str, delimiter) -> list:
    """Tries to split a string by the given delimiter(s).

    :param s: The string to split.
    :param delimiter: Either a single string, or a tuple of strings (i.e. (',', ';').
    :return: Returns the string split into a list.
    """
    if isinstance(delimiter, tuple):
        for d in delimiter:
            if d in s:
                return [i.strip() for i in s.split(d)]
    elif delimiter in s:
        return s.split(delimiter)

    return [s]


class Job:
    def __init__(self, name):
        self.fio_command = None
        self.name = name


class Mem:
    def __init__(self):
        self.fio_file = None
        self.fio_lat_file_pref = None
        self.rw = '└(◉◞౪◟◉)┘'
        self.io_stddev = 0
        self._schedulers = None
        self.device = None
        self.runtime = None
        self._fio_ramp_time = 0
        self._blktrace_delay = 0
        self._filter_stddev = None
        self._filter_abnormal = False
        self.output_file = None
        self.jobs = None
        self.output_column_order = ['workload', 'scheduler', 'rw', 'clat', 'user', 'file system', 'block layer', 'driver', 'device']

        self.current_processes = set()

        # Formatters
        self.format_blktrace = 'blktrace -d %s -w %s'  # device, runtime
        self.blkparse_file = 'blkparse.txt'
        self.format_blkparse = 'blkparse -i %s -o ' + self.blkparse_file  # device short
        self.format_blkrawverify = 'blkrawverify %s'  # file prefix
        self.format_fio_clat = '%s_clat.1.log'  # fio file prefix
        self.format_fio_slat = '%s_slat.1.log'  # fio file prefix
        self.format_fio = '%s --output-format=json'  # fio command

        # Regex
        self.re_device = re.compile(r'/dev/(.*)')

        # Validity
        self.valid_settings = {'blktrace_delay', 'device', 'filter_stddev', 'filter_abnormal', 'fio_command',
                               'fio_file', 'fio_lat_file_pref', 'fio_ramp_time', 'runtime', 'schedulers'}

    @property
    def schedulers(self) -> set:
        return self._schedulers

    @schedulers.setter
    def schedulers(self, value):
        self._schedulers = set(try_split(value, ','))

    @property
    def blktrace_delay(self) -> int:
        return self._blktrace_delay

    @blktrace_delay.setter
    def blktrace_delay(self, value: int):
        conv_value = ignore_exception(ValueError, -1)(float)(value)

        if conv_value < 1:
            raise ValueError('Blktrace delay given is < 0: %s' % value)

        self._blktrace_delay = conv_value

    @property
    def fio_ramp_time(self) -> int:
        return self._fio_ramp_time

    @fio_ramp_time.setter
    def fio_ramp_time(self, value: int):
        conv_value = ignore_exception(ValueError, -1)(float)(value)

        if conv_value < 1:
            raise ValueError('Fio ramp time given is < 0: %s' % value)

        self._fio_ramp_time = conv_value

    @property
    def filter_stddev(self) -> int:
        return self._filter_stddev

    @filter_stddev.setter
    def filter_stddev(self, value: int):
        conv_value = ignore_exception(ValueError, -1)(float)(value)

        if conv_value < 1:
            raise ValueError('Filter stddev given is < 0: %s' % value)

        self._filter_stddev = conv_value

    @property
    def filter_abnormal(self) -> int:
        return self._filter_abnormal

    @filter_abnormal.setter
    def filter_abnormal(self, value: int):
        conv_value = ignore_exception(ValueError, False)(bool)(value)
        self._filter_abnormal = conv_value

    def process_jobs(self) -> bool:
        """Executes each job.

        :return: Returns True if successful, else False.
        """
        for job in self.jobs:
            if not Mem.execute(job):
                return False
        return True

    def execute(self, job) -> bool:
        """Executes the workloads.

        :return: Returns True if successful, else False.
        """
        for scheduler in self.schedulers:
            log('Executing scheduler %s' % scheduler)

            if not change_scheduler(scheduler, self.device):
                log('Unable to change scheduler %s for device %s' % (scheduler, self.device))
                return False

            if not self._execute_workload(job):
                print('Workload failed to execute')
                return False

            # Metrics
            if not self._process_results(job, scheduler):
                log('Unable to process workload results')
                return False

        return True

    def _execute_workload(self, job):
        """Executes a workload.

        :return: Return True if successful, otherwise False.
        """
        log('Executing workload')

        device_short = Mem.re_device.findall(self.device)[0]
        clear_caches(self.device)

        blktrace = Mem.format_blktrace % (Mem.device, self.runtime)
        fio = Mem.format_fio % job.fio_command

        log('Start time: %s' % strftime('%m/%d/%y %I:%M:%S %p', localtime()))
        out = run_parallel_commands([('blktrace', Mem.blktrace_delay, blktrace), ('fio', 0, fio)])
        log('Stop time: %s' % strftime('%m/%d/%y %I:%M:%S %p', localtime()))

        # Error running commands
        if out is None or 'blktrace' in out and out['blktrace'] is None:
            log('Error running workload')
            return False

        blktrace_out, _ = out['blktrace']
        workload_out, _ = out['fio']

        if blktrace_out is None or workload_out is None:
            log('Error running workload')
            return False

        # Run blkparse
        blkparse = Mem.format_blkparse % device_short
        _, _ = run_command(blkparse, ignore_output=True)

        # Run blkrawverify
        blkrawverify = Mem.format_blkrawverify % device_short
        blkrawverify_out, _ = run_command(blkrawverify)
        log('BLKRAWVERIFY Output')
        log(blkrawverify_out)

        # Grab fio metrics from output
        self._grab_fio_metrics(workload_out)

        return True

    def _process_results(self, job, scheduler):
        """Processes a workload.

        :return: Returns True if successful, otherwise False.
        """
        io_map = OrderedDict()

        start_lba = get_start_lba(Mem.fio_file)

        clat_file = Mem.format_fio_clat % Mem.fio_lat_file_pref
        slat_file = Mem.format_fio_slat % Mem.fio_lat_file_pref
        blkparse_file = Mem.blkparse_file

        if not os.path.isfile(clat_file):
            log('Fio clat file doesn\'t exist: %s' % clat_file)
            return False

        if not os.path.isfile(slat_file):
            log('Fio slat file doesn\'t exist: %s' % slat_file)
            return False

        if not os.path.isfile(blkparse_file):
            log('Blkparse file doesn\t exist: %s' % blkparse_file)
            return False

        # Necessary for random IO if duplicate address is read
        io_list = []

        # Read FIO clat and slat into IO map
        with open(clat_file) as cf:
            with open(slat_file) as sf:
                clat_line = cf.readline().strip()

                while clat_line:
                    slat_line = sf.readline().strip()
                    timestamp, clat, data_direction, block_size, offset = clat_line.split(',')
                    timestamp, slat, data_direction, block_size, offset = slat_line.split(',')

                    lba = start_lba + int(offset) // 512
                    io = IO(int(timestamp), lba)
                    io.clat = int(clat) * 0.001  # convert from ns to μs
                    io.slat = int(slat) * 0.001  # convert from ns to μs

                    # If io already in map, append to existing io to secondary
                    if lba in io_map:
                        io_list.append(io_map[lba])

                    io_map[lba] = io

                    clat_line = cf.readline().strip()

        # Read blkparse Q, D, C into IO map
        with open(blkparse_file) as bf:
            for line in bf:
                line_split = line.strip().split()

                # Hitting stats at bottom of file
                if len(line_split) < 3:
                    break

                timestamp = float(line_split[3])
                action = line_split[5]

                if timestamp + 0.1 < Mem.fio_ramp_time:
                    continue

                if action in ('Q', 'D', 'S', 'C'):
                    try:
                        sector, blocks = int(line_split[7]), int(line_split[9])
                    except ValueError:
                        log('Invalid line: %s' % ''.join(line_split))

                    if sector not in io_map:
                        continue

                    # Convert from s to us
                    if action == 'Q':
                        io_map[sector].q = timestamp * 10 ** 6
                    elif action == 'D':
                        io_map[sector].d = timestamp * 10 ** 6
                    elif action == 'S':
                        io_map[sector].s = timestamp * 10 ** 6
                    elif action == 'C':
                        io_map[sector].c = timestamp * 10 ** 6

        io_list.extend(io_map.values())

        # Log if not all IOs are valid
        self._validate_ios(io_list)

        self._print_metrics(io_list, job, scheduler)

        return True

    def _grab_fio_metrics(self, out):
        """Grabs specific metrics from fio.

        :param out: Output of fio (should be json).
        """
        data = json.loads(out, encoding='utf-8')
        job = data['jobs'][0]
        Mem.rw = data['global options']['rw']

        if Mem.rw in ('read', 'randread'):
            Mem.stddev = float(job['read']['clat_ns']['stddev']) * 0.001  # convert from ns to μs
        else:
            Mem.stddev = float(job['write']['clat_ns']['stddev']) * 0.001  # convert from ns to μs

        log('Clat of stddev found to be: %s' % Mem.io_stddev)

    def _print_metrics(self, io_list, job, scheduler):
        """Outputs the io metrics.

        :param io_list: A list of the IOs.
        """
        ios_counted = 0
        avg_clat = 0
        avg_slat = 0
        avg_q2c = 0
        avg_q2d = 0
        avg_d2c = 0
        avg_d2s = 0
        avg_s2c = 0
        avg_fs = 0

        for io in io_list:
            if not io.valid:
                continue

            ios_counted += 1
            avg_clat += io.clat
            avg_slat += io.slat
            avg_q2c += io.q2c
            avg_q2d += io.q2d
            avg_d2c += io.d2c
            avg_d2s += io.d2s
            avg_s2c += io.s2c
            avg_fs += io.fs

        if ios_counted > 0:
            avg_clat /= ios_counted
            avg_slat /= ios_counted
            avg_q2c /= ios_counted
            avg_q2d /= ios_counted
            avg_d2c /= ios_counted
            avg_d2s /= ios_counted
            avg_s2c /= ios_counted
            avg_fs /= ios_counted

        # Convert metrics from ns to μs
        print_and_log('Results of workload:')
        print_and_log('clat [μs]: %.6f' % avg_clat)
        print_and_log('slat [μs]: %.6f' % avg_slat)
        print_and_log('q2c [μs]: %.6f' % avg_q2c)
        print_and_log('q2d [μs]: %.6f' % avg_q2d)
        print_and_log('d2c [μs]: %.6f' % avg_d2c)
        print_and_log('d2s [μs]: %.6f' % avg_d2s)
        print_and_log('s2c [μs]: %.6f' % avg_s2c)
        print_and_log('fs [μs]: %.6f' % avg_fs)

        if Mem.output_file is not None:
            with open(Mem.output_file, 'a') as file:
                file.write('%s,%s,%s,%s,%s,%s,%s,%s,%s\n' %
                           (job.name, scheduler, Mem.rw, avg_clat, avg_slat, avg_fs, avg_q2d, avg_d2s, avg_s2c))

    def _validate_ios(self, io_list):
        """Validates the ios are all valid.

        :param io_list: A list of the IOs.
        :return: Returns True if all IOs are valid, otherwise False.
        """
        num_invalid = 0
        num_valid = 0
        with open('invalid-io.log', 'w') as ma:
            for io in io_list:
                if not io.valid:
                    ma.write('IO is not valid at timestamp %s, address %s (%s)\n' % (io.timestamp, io.address, io.invalid_property))
                    num_invalid += 1
                else:
                    num_valid += 1

        log('Number of invalid IOs: %s' % num_invalid)
        log('Number of valid IOs: %s' % num_valid)

        return num_invalid == 0


class IO:
    def __init__(self, timestamp, address):
        self.timestamp = timestamp
        self.address = address
        self.clat = None
        self.slat = None
        self.q = None
        self.d = None
        self.s = None
        self.c = None
        self.invalid_property = None

    @property
    def d2c(self):
        return self.c - self.d

    @property
    def fs(self):
        return self.clat - self.q2c

    @property
    def q2c(self):
        return self.c - self.q

    @property
    def q2d(self):
        return self.d - self.q

    @property
    def d2s(self):
        return self.s - self.d

    @property
    def s2c(self):
        return self.c - self.s

    @property
    def valid(self):
        if self.clat is None:
            self.invalid_property = 'missing clat'
            return False

        if self.slat is None:
            self.invalid_property = 'missing slat'
            return False

        if self.q is None:
            self.invalid_property = 'missing q'
            return False

        if self.d is None:
            self.invalid_property = 'missing d'
            return False

        if self.c is None:
            self.invalid_property = 'missing c'
            return False

        if self.s is None:
            self.invalid_property = 'missing s'
            return False

        if Mem.filter_abnormal and self.fs < 0:
            self.invalid_property = 'fs < 0'
            return False

        if Mem.filter_stddev is not None:
            if abs(Mem.filter_stddev * Mem.io_stddev) <= abs(self.clat):
                self.invalid_property = 'abnormal stddev'
                return False

        return True


Mem = Mem()


# region termination
def sig_handler(signal, frame):
    if Mem.current_processes:
        kill_processes(Mem.current_processes)
        Mem.current_processes.clear()

    sys.exit(0)
# endregion


# region processes
def get_failed_processes(processes: set) -> set:
    """Returns the processes which are failed.
    :param processes: A set of tuples of command names and processes.
    :return: A set of failed processes.
    """
    failed_processes = set()

    for command_name, process in processes:
        rc = process.poll()

        if rc is not None:  # Done processing
            if rc != 0:  # Return code other than 0 indicates error
                failed_processes.add((command_name, process))

    return failed_processes


def get_finished_processes(processes: set) -> set:
    """Returns the processes which are finished.
    :param processes: A set of tuples of command names and processes.
    :return: A set of finished processes.
    """
    finished_processes = set()

    for command_name, process in processes:
        rc = process.poll()

        if rc is not None:  # Done processing
            finished_processes.add((command_name, process))

    return finished_processes


def kill_processes(processes: set):
    """Kills the processes.
    :param processes: A set of tuples of command names and processes.
    """
    for command_name, process in processes:
        try:
            log('Killing process %s' % process)
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except:
            pass


def print_processes(processes: set):
    """Prints the each processes's output.
    :param processes: A set of tuples of command names and processes.
    """
    for command_name, process in processes:
        out, err = process.communicate()
        if out:
            log(out.decode('utf-8'))
        if err:
            log(err.decode('utf-8'))
# endregion


# region utilities
def print_and_log(*args, **kwargs):
    print(*args, **kwargs)
    log(*args, **kwargs)


def log(*args, **kwargs):
    """Logs a message if logging is enabled.
    :param args: The arguments.
    :param kwargs: The keyword arguments.
    """
    if args:
        args_rem = [a.strip() if isinstance(a, str) else a for a in args][1:]
        message = args[0]

        for line in str(message).split('\n'):
            logging.debug(line, *args_rem, **kwargs)
    else:
        logging.debug(*args, **kwargs)


def ignore_exception(exception=Exception, default_val=None):
    """A decorator function that ignores the exception raised, and instead returns a default value.
    :param exception: The exception to catch.
    :param default_val: The default value.
    :return: The decorated function.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except exception as e:
                log(str(e))
                return default_val
        return wrapper
    return decorator
# endregion


# region commands
def get_start_lba(file: str) -> int:
    """Returns the starting LBA for the fio file.

    :param file: The file.
    :return: The starting lba of the file.
    """
    log('Retrieving starting lba for %s' % file)

    out, _ = run_command('hdparm --fibmap %s' % file)

    line_split = out.strip().split('\n')
    line = line_split[3]
    v_split = line.split()
    start_lba = int(v_split[1])

    log('Start lba found to be %s' % start_lba)

    return start_lba


def check_trace_commands() -> bool:
    """Validates whether the required tracing commands exists on the system.
    :return: Returns True if commands exists, else False.
    """
    if not command_exists('blktrace'):
        log('blktrace is not installed. Please install via \'sudo apt install blktrace\'')
        return False

    if not command_exists('blkparse'):  # Included with blktrace
        log('blkparse is not installed. Please install via \'sudo apt install blktrace\'')
        return False

    if not command_exists('btt'):  # Included with blktrace
        log('btt is not installed. Please install via \'sudo apt install blktrace\'')
        return False

    if not command_exists('hdparm'):  # Included in most distros of Linux
        log('hdparm is not installed. Please install via \'sudo apt install hdparm\'')
        return False

    return True


def command_exists(command: str) -> bool:
    """Returns whether the given command exists on the system.
    :param command: The command.
    :return: Returns True if exists, else False.
    """
    log('Checking if dependency %s exists' % command)

    rc = run_system_command('command -v %s' % command)

    return rc == 0


def clear_caches(device: str):
    """Clears various data caches. Should be run before each benchmark.
    :param device: The device to clear the caches for.
    """
    # Writes any data buffered in memory out to disk
    run_system_command('sync')

    # Drops clean caches
    run_system_command('echo 3 > /proc/sys/vm/drop_caches')

    # Calls block device ioctls to flush buffers
    run_system_command('blockdev --flushbufs %s' % device)

    # Flushes the on-drive write cache buffer
    run_system_command('hdparm -F %s' % device)


def get_device_major_minor(device: str) -> str:
    """Returns a string of the major, minor of a given device.
    :param device: The device.
    :return: A string of major,minor.
    """
    log('Retrieving major,minor for device %s' % device)

    out, _ = run_command('stat -c \'%%t,%%T\' %s' % device)

    return out if not out else out.strip()


def get_schedulers(device: str) -> list:
    """Returns a list of available schedulers for a given device.
    :param device: The device.
    :return: Returns a list of schedulers.
    """
    log('Retrieving schedulers for device %s' % device)

    matches = Mem.re_device.findall(device)

    if not matches:
        log('Unable to find schedulers for device')
        return []

    out, rc = run_command('cat /sys/block/%s/queue/scheduler' % matches[0])

    if rc != 0:
        log('Unable to find schedulers for device')
        return []

    ret = out.replace('[', '').replace(']', '')

    log('Found the following schedulers for device %s: %s' % (device, ret))

    return ret.split()


def change_scheduler(scheduler: str, device: str):
    """Changes the I/O scheduler for the given device.
    :param scheduler: The I/O scheduler.
    :param device: The device.
    :return: Returns True if successful, else False.
    """
    log('Changing scheduler for device %s to %s' % (device, scheduler))

    command = 'bash -c "echo %s > /sys/block/%s/queue/scheduler"' % (scheduler, Mem.re_device.findall(device)[0])

    out, rc = run_command(command)

    return rc == 0


def run_parallel_commands(command_map: list, abort_on_failure: bool=True):
    """Runs multiple commands in parallel via subprocess communication. A single failed process results in the remaining
    being stopped.

    :param command_map: A command mapping which contains a list of tuples containing (command name, the command itself).
    :param abort_on_failure: Whether to abort if a single process failures, otherwise continues. Defaults to True.
    :return: A dictionary where key = command name and value = tuple of (the output, the return code).
    """
    log('Running commands in parallel')

    Mem.current_processes.clear()
    completed_processes = set()
    last_delay = 0

    for command_name, delay, command in sorted(command_map, key=lambda x: x[1]):
        try:
            # Delay command execution based on specified delay
            # Note: This isn't quite exact, due to timing issues and the concurrency limit
            if delay > last_delay:
                time.sleep(delay - last_delay)
                last_delay = delay

            log('Running command %s' % command)

            args = shlex.split(command)

            p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                                 preexec_fn=os.setsid)

            Mem.current_processes.add((command_name, p))
        except (ValueError, subprocess.CalledProcessError, FileNotFoundError) as err:
            log(err)
            if abort_on_failure:
                break

    else:
        # Wait for processes to finish
        while len(Mem.current_processes) > 0:
            time.sleep(0.5)

            finished_processes = get_finished_processes(Mem.current_processes)

            Mem.current_processes.difference_update(finished_processes)
            completed_processes.update(finished_processes)

            if abort_on_failure:
                failed_processes = get_failed_processes(finished_processes)

                if failed_processes:  # Something failed, abort!
                    print_processes(failed_processes)
                    kill_processes(Mem.current_processes)
                    return None

        ret = dict()

        # Grab outputs from completed processes
        for command_name, process in completed_processes:
            out, err = process.communicate()

            rc = process.returncode

            if err:
                log(err.decode('utf-8'))

            ret[command_name] = (out.decode('utf-8'), rc)

        return ret

    # We got here because we aborted, continue the abortion...
    failed_processes = get_failed_processes(Mem.current_processes)
    print_processes(failed_processes)

    kill_processes(Mem.current_processes)

    return None


def run_system_command(command: str, silence: bool=True) -> int:
    """Runs a system command.
    :param command: The command.
    :param silence: (OPTIONAL) Whether to silence the console output. Defaults to True.
    :return: The return code.
    """
    if silence:
        command = '%s >/dev/null 2>&1' % command

    log('Running command %s' % command)

    rc = os.system(command)
    return rc


def run_command(command: str, inp: str='', ignore_output: bool = False) -> (str, int):
    """Runs a command via subprocess communication.
    :param command: The command.
    :param inp: (OPTIONAL) Command input.
    :param ignore_output: (OPTIONAL) Whether to ignore the output. Defaults to False.
    :return: A tuple containing (the output, the return code).
    """
    log('Running command %s with input %s' % (command, inp))

    try:
        args = shlex.split(command)

        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                             preexec_fn=os.setsid)

        Mem.current_processes.add((command, p))

        if ignore_output:
            rc = p.wait()

            Mem.current_processes.clear()

            if rc != 0:
                log('Error, return code is not zero!')

            return '', rc
        else:
            out, err = p.communicate(inp)

            rc = p.returncode

            Mem.current_processes.clear()

            if err:
                log(err.decode('utf-8'))

            return out.decode('utf-8'), rc
    except (ValueError, subprocess.CalledProcessError, FileNotFoundError) as err:
        log(err)
        return None, None
    finally:
        Mem.current_processes.clear()
# endregion


# region command-line
def usage():
    """Displays command-line information."""
    name = os.path.basename(__file__)
    print('%s %s' % (name, __version__))
    print('Usage: %s <file> [-o file]' % name)
    print('Command Line Arguments:')
    print('<file>            : The configuration file to use.')
    print('-o <file>         : (OPTIONAL) Output metrics to a csv file.')


def parse_args(argv: list) -> bool:
    """Parses the supplied arguments and persists in memory.
    :param argv: A list of arguments.
    :return: Returns a boolean as True if parsed correctly, otherwise False.
    """
    try:
        opts, args = getopt(argv, 'ho:ps:')

        for opt, arg in opts:
            if opt == '-h':
                return False
            elif opt == '-o':
                Mem.output_file = arg

        return True
    except GetoptError as err:
        log(err)
        return False


def parse_config_file(file_path: str) -> bool:
    """Parses the supplied file and persists data into memory.
    :param file_path: The file.
    :return: Returns True if settings are valid, else False.
    """
    log('Parsing configuration file: %s' % file_path)
    Mem.config_file = file_path
    jobs = []

    if not os.path.isfile(Mem.config_file):
        sys.exit('File not found: %s' % Mem.config_file)

    config = configparser.ConfigParser()
    try:
        config.read(file_path, 'utf-8')
    except configparser.ParsingError as err:
        log('Invalid syntax in config file found!')
        log(err)
        return False

    for section in config.sections():
        if section != 'global':
            job = Job(section)

        for key, value in config[section].items():
            if not is_valid_setting(key):
                log('Invalid syntax in config file found: %s=%s' % (key, value))
                return False

            try:
                if section != 'global':
                    setattr(job, key, value)
                else:
                    setattr(Mem, key, value)
            except ValueError:
                log('Invalid syntax in config file found: %s=%s' % (key, value))
                return False

        if section != 'global':
            jobs.append(job)

    Mem.jobs = jobs
    return True


def is_valid_setting(setting: str) -> bool:
    """Returns whether the config setting is valid.
    :return: Returns True if setting is valid, else False.
    """
    log('Checking whether setting %s is valid' % setting)

    if not setting:
        return False

    return setting in Mem.valid_settings


# endregion


def main(argv: list):
    # Help flag dominates all args
    if '-h' in argv:
        usage()
        sys.exit(1)

    # Validate os
    ps = platform.system()
    if ps != 'Linux':
        print('OS is %s, must be Linux' % ps)
        sys.exit(1)

    # Validate privileges
    if os.getuid() != 0:
        print('Script must be run with administrative privileges. Try sudo %s' % __file__)
        sys.exit(1)

    # Set logging as early as possible
    logging.basicConfig(filename='tracer.log', level=logging.DEBUG, format='%(asctime)s - %(message)s')

    if len(argv) == 0:
        usage()
        sys.exit(1)

    # Validate settings
    if not parse_config_file(argv[0]):
        sys.exit(1)

    # Validate arguments
    if not parse_args(argv[1:]):
        usage()
        sys.exit(1)

    if not check_trace_commands():
        sys.exit(1)

    # Validate schedulers
    valid_schedulers = get_schedulers(Mem.device)
    for scheduler in Mem.schedulers:
        if scheduler not in valid_schedulers:
            log('Invalid scheduler! Given %s, expected %s' % (scheduler, valid_schedulers))
            sys.exit(1)

    # Create output file (will be appended to)
    if Mem.output_file is not None:
        if not os.path.isfile(Mem.output_file):
            with open(Mem.output_file, 'w') as file:
                file.write(','.join(Mem.output_column_order))
                file.write('\n')

    # Execute workload
    if not Mem.process_jobs():
        sys.exit(1)


if __name__ == '__main__':
    # Add signal handlers for graceful termination
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    main(sys.argv[1:])

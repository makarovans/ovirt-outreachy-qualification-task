#!/usr/bin/env python
import os
import re
import numpy
import pandas as pd
import multiprocessing
from datetime import datetime
import pytz
import argparse
from progressbar import ProgressBar
from collections import OrderedDict


class TextColor:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    GRAY = '\033[37m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


TIME_REGEX = re.compile(r'^\d{4}-[0-1]\d-[0-3]\d [0-2]\d:[0-5]\d:[0-5]\d.\d{3}[+\-][0-2]\d[0-5]\d$')
DATE_EPOCH = datetime(1970, 1, 1, tzinfo=pytz.UTC)


class LogMsg:
    msg_type_normal_regex = {
        # info
        'virObjectRef': [
            re.compile(r'^[0-9]+:OBJECT_REF:obj=0x[0-9a-f]+$'),
        ],
        'virObjectUnref': [
            re.compile(r'^[0-9]+:OBJECT_UNREF:obj=0x[0-9a-f]+$'),
            re.compile(r'^[0-9]+:OBJECT_DISPOSE:obj=0x[0-9a-f]+$'),
        ],
        'virObjectNew': [
            re.compile(r'^[0-9]+:OBJECT_NEW:obj=0x[0-9a-f]+ classname=(vir|qemu)[A-Za-z]+$'),
        ],
        'qemuMonitorIOProcess': [
            re.compile(r'^[0-9]+:QEMU_MONITOR_IO_PROCESS:mon=0x[0-9a-f]+ buf=.+(\n)*len=[0-9]+$'),
            re.compile(r'^[0-9]+:QEMU_MONITOR_IO_PROCESS:mon=0x[0-9a-f]+ buf=(.+\n)+len=[0-9]+$'),
        ],
        'qemuMonitorIOWrite': [
            re.compile(r'^[0-9]+:QEMU_MONITOR_IO_WRITE:mon=0x[0-9a-f]+ buf=.+\nlen=[0-9]+ ret=[0-9]+ errno=[0-9]+$'),
            re.compile(r'^[0-9]+:QEMU_MONITOR_IO_SEND_FD:mon=0x[0-9a-f]+ fd=[0-9]+ ret=[0-9]+ errno=[0-9]+'),
        ],
        'qemuMonitorSend': [
            re.compile(r'^[0-9]+:QEMU_MONITOR_SEND_MSG:mon=0x[0-9a-f]+ msg={.+}\nfd=[\-0-9]'),
        ],
        'virFirewallApplyRule': [
            re.compile(r"^[0-9]+:Applying rule '.*(.*\n)*'$"),
            re.compile(r"^[0-9]+:Invoking query 0x[0-9a-f]+ with '.*(.*\n)*'$"),
        ],
        'virDBusCall': [
            re.compile(r"^[0-9]+:DBUS_METHOD_CALL:'[a-zA-Z0-9.]+' on '[a-zA-Z0-9/]+' at '[a-zA-Z0-9.]+'$"),
            re.compile(r"^[0-9]+:DBUS_METHOD_REPLY:'[a-zA-Z0-9.]+' on '[a-zA-Z0-9/]+' at '[a-zA-Z0-9.]+'$"),
        ],
        'virFirewallApplyGroup': [
            re.compile(r"^[0-9]+:Starting transaction for firewall=0x[0-9a-f]+ group=0x[0-9a-f]+ flags=[0-1]$"),
        ],
        'virSecuritySELinuxSetFileconHelper': [
            re.compile(r"^[0-9]+:Setting SELinux context on '[a-zA-Z0-9.\-/]+' to '[a-z_:0-9,]+'$"),
        ],
        'virSecurityDACSetOwnershipInternal': [
            re.compile(r"^[0-9]+:Setting DAC user and group on '[a-zA-Z0-9.\-/]+' to '[:0-9]+'$"),
        ],
        'virNetDevProbeVnetHdr': [
            re.compile(r'^[0-9]+:Enabling IFF_VNET_HDR$'),
        ],
        'qemuMonitorClose': [
            re.compile(r'^[0-9]+:QEMU_MONITOR_CLOSE:mon=0x[0-9a-f]+ refs=[0-9]+$'),
        ],
        'qemuMonitorOpenInternal': [
            re.compile(r'^[0-9]+:QEMU_MONITOR_NEW:mon=0x[0-9a-f]+ refs=[0-9]+ fd=[0-9]+$'),
        ],
        # debug
        'virAccessManagerCheckConnect': [
            re.compile(r'^[0-9]+:manager=0x[0-9a-f]+\(name=(stack|none)\) driver=QEMU perm=[0-9]+$'),
        ],
        'virAccessManagerCheckDomain': [
            re.compile(r'^[0-9]+:manager=0x[0-9a-f]+\(name=(stack|none)\) driver=QEMU domain=0x[0-9a-f]+ perm=[0-9]+$'),
        ],
        'virThreadJobClear': [
            re.compile(r'^[0-9]+:Thread [0-9]+ \(virNetServerHandleJob\) finished job [a-zA-Z0-9]+ with ret=0$'),
        ],
        'virThreadJobSet': [
            re.compile(r'^[0-9]+:Thread [0-9]+ \(virNetServerHandleJob\) is now running job [a-zA-Z0-9]+$'),
        ],
        'virDomainDispose': [
            re.compile(r'^[0-9]+:release domain 0x[0-9a-f]+ [a-zA-Z0-9]+ [a-f0-9\-]+$'),
        ],
        'virFileClose': [
            re.compile(r'^[0-9]+:Closed fd [1-9][0-9]*\n?\'?$'),
        ],
        'virCgroupGetValueStr': [
            re.compile(r'^[0-9]+:Get value [/\\a-zA-Z0-9,\-._]+$'),
        ],
        'qemuDomainObjExitMonitorInternal': [
            re.compile(r'^[0-9]+:Exited monitor \(mon=0x[0-9a-f]+ vm=0x[0-9a-f]+ name=[a-zA-Z0-9]+\)$'),
        ],
        'qemuDomainObjEnterMonitorInternal': [
            re.compile(r'^[0-9]+:Entering monitor \(mon=0x[0-9a-f]+ vm=0x[0-9a-f]+ name=[a-zA-Z0-9]+\)$'),
        ],
        'qemuMonitorBlockStatsUpdateCapacity': [
            re.compile(r'^[0-9]+:stats=0x[0-9a-f]+, backing=0$'),
            re.compile(r'^[0-9]+:mon:0x[0-9a-f]+ vm:0x[0-9a-f]+ json:1 fd:[1-9][0-9]*$'),
        ],
        'qemuMonitorGetAllBlockStatsInfo': [
            re.compile(r'^[0-9]+:ret_stats=0x[0-9a-f]+, backing=0$'),
            re.compile(r'^[0-9]+:mon:0x[0-9a-f]+ vm:0x[0-9a-f]+ json:1 fd:[1-9][0-9]*$'),
        ],
        'virConnectSupportsFeature': [
            re.compile(r'^[0-9]+:conn=0x[0-9a-f]+, feature=[0-9]+$'),
        ],
        'qemuMonitorGetBlockIoThrottle': [
            re.compile(r'^[0-9]+:device=0x[0-9a-f]+, reply=0x[0-9a-f]+$'),
            re.compile(r'^[0-9]+:mon:0x[0-9a-f]+ vm:0x[0-9a-f]+ json:1 fd:[1-9][0-9]*$'),
        ],
        'qemuGetProcessInfo': [
            re.compile(r'^[0-9]+:Got status for [0-9]+/[0-9]+ user=[0-9]+ sys=[0-9]+ cpu=[0-9]+ rss=[0-9]+$'),
        ],
        'virDomainFree': [
            re.compile(r'^[0-9]+:dom=0x[0-9a-f]+, \(VM:name=[a-zA-Z0-9]+, uuid=[a-f0-9\-]+\)$'),
        ],
        'virDomainGetBlockIoTune': [
            re.compile(r'^[0-9]+:dom=0x[0-9a-f]+, \(VM:name=[a-zA-Z0-9]+, uuid=[a-f0-9\-]+\), disk=sda, params=(\(nil\)|0x[0-9a-f]+), nparams=[0-9]+, flags=[0-9]+$'),
        ],
        'virDomainGetMetadata': [
            re.compile(r'^[0-9]+:dom=0x[0-9a-f]+, \(VM:name=[a-zA-Z0-9]+, uuid=[a-f0-9\-]+\), type=[0-9]+, uri=\'http://[a-z0-9./]+\', flags=[0-9]+$'),
        ],
        'virNodeGetMemoryStats': [
            re.compile(r'^[0-9]+:conn=0x[0-9a-f]+, cellNum=0, params=(\(nil\)|0x[0-9a-f]+), nparams=[0-9]+, flags=[0-9]+$'),
        ],
        'virConnectGetAllDomainStats': [
            re.compile(r'^[0-9]+:conn=0x[0-9a-f]+, stats=0x0, retStats=0x[0-9a-f]+, flags=0x0$'),
        ],
        'virDomainGetControlInfo': [
            re.compile(r'^[0-9]+:dom=0x[0-9a-f]+, \(VM:name=[a-zA-Z0-9]+, uuid=[a-f0-9\-]+\), info=0x[0-9a-f]+, flags=[0-9]+$'),
        ],
        'virNodeDeviceDispose': [
            re.compile(r'^[0-9]+:release dev 0x[0-9a-f]+ [a-zA-Z0-9_]+$'),
        ],
        'virCgroupDetect': [
            re.compile(r'^[0-9]+:group=0x[0-9a-f]+ controllers=(-1|[0-9]+) path= parent=\(nil\)$'),
            re.compile(r'^[0-9]+:Auto-detecting controllers$'),
            re.compile(r'^[0-9]+:Controller \'(name=){0,1}[a-z_]+\' present=yes$'),
            re.compile(r'^[0-9]+:Detected mount/mapping (0:cpu|1:cpuacct) at [/a-z,]+ in [0-9a-zA-Z.\\/\-]+ for pid [0-9]+$'),
        ],
        'virAccessManagerCheckNodeDevice': [
            re.compile(r'^[0-9]+:manager=0x[0-9a-f]+\(name=(stack|none)\) driver=QEMU nodedev=0x[0-9a-f]+ perm=[0-1]$'),
        ],
        'virNodeDeviceLookupByName': [
            re.compile(r'^[0-9]+:conn=0x[0-9a-f]+, name=[a-zA-Z0-9_]+$'),
        ],
        'virCgroupMakeGroup': [
            re.compile(r'^[0-9]+:Make group [/,a-zA-Z0-9.\\\-_]+$'),
            re.compile(r'^[0-9]+:Make controller [/,a-zA-Z0-9.\\\-_]+$'),
            re.compile(r'^[0-9]+:Done making controllers for group$'),
        ],
        'virCommandRunAsync': [
            re.compile(r'^[0-9]+:About to run .+$'),
            re.compile(r'^[0-9]+:Command result 0, with PID [0-9]+$'),
        ],
        'virCommandRun': [
            re.compile(r'^[0-9]+:Result (exit )?status 0, stdout:\'.*\' stderr:\'.*(\')?$', re.DOTALL),
        ],
        'virNodeDeviceGetXMLDesc': [
            re.compile(r'^[0-9]+:dev=0x[0-9a-f]+, conn=0x[0-9a-f]+, flags=[0-9]+$'),
        ],
        'virDomainGetInfo': [
            re.compile(r'^[0-9]+:dom=0x[0-9a-f]+, \(VM:name=[a-zA-Z0-9]+, uuid=[a-f0-9\-]+\), info=0x[0-9a-f]+$'),
        ],
        'virNodeGetCPUMap': [
            re.compile(r'^[0-9]+:conn=0x[0-9a-f]+, cpumap=\(nil\), online=\(nil\), flags=0$'),
        ],
    }

    error_regex = [
        re.compile(r"error", re.IGNORECASE),
        re.compile(r"not ", re.IGNORECASE),
        re.compile(r"doesn't", re.IGNORECASE),
        re.compile(r"\"[a-zA-Z_]*invalid[a-zA-Z_]*\":[-1-9]+", re.IGNORECASE),
        re.compile(r"\"[a-zA-Z_]*invalid[a-zA-Z_]*\":true", re.IGNORECASE),
        re.compile(r"invalid", re.IGNORECASE),
        re.compile(r"\"[a-zA-Z_]*failed[a-zA-Z_]*\":[-1-9]+", re.IGNORECASE),
        re.compile(r"\"[a-zA-Z_]*failed[a-zA-Z_]*\":true", re.IGNORECASE),
        re.compile(r"fail", re.IGNORECASE),
        re.compile(r"fatal", re.IGNORECASE),
    ]

    def __init__(self):
        self.msg = None
        self.type = None
        self.suspicious_level = 'Mismatch normal'
        self.error_contains = False

    def parse(self, line):
        self.type, self.msg = line.split(':', 1)
        if self.type not in LogMsg.msg_type_normal_regex:
            self.suspicious_level = 'Unknown message type'
        else:
            for regex in LogMsg.msg_type_normal_regex[self.type]:
                if regex.match(self.msg):
                    self.suspicious_level = 'Good'
                    break

        for error_regex in LogMsg.error_regex:
            if error_regex.search(self.msg):
                self.error_contains = True
                break

        return self

    def to_error_str(self):
        result = TextColor.BOLD + TextColor.BLUE + self.type + TextColor.END + ': '
        # Find error places #
        error_pos = []
        for error_regex in LogMsg.error_regex:
            if error_regex.search(self.msg):
                error_pos.extend([match for match in error_regex.finditer(self.msg)])
        # Highlight errors #
        pos = 0
        for match in sorted(error_pos, key=lambda x: x.start()):
            if pos >= match.end():
                continue
            if pos < match.start():
                result += self.msg[pos:match.start()]
                pos = match.start()
            result += TextColor.BOLD + TextColor.RED + self.msg[pos:match.end()] + TextColor.END
            pos = match.end()
        if pos < len(self.msg):
            result += self.msg[pos:]

        return result.replace('\n', '\\n')

    def __str__(self):
        return self.msg


class CommonLogItem:
    def __init__(self):
        self.line_index = None
        self.date = None
        self.thread = None
        self.level = None
        self.msg = None

    def parse(self, line, ind):
        # Set line index and date
        self.line_index = ind
        self.date = (datetime.strptime(line[:28], "%Y-%m-%d %H:%M:%S.%f%z") - DATE_EPOCH).total_seconds()
        # Split log line
        splits = [item.strip() for item in line[28:].split(':') if item != '']
        if len(splits) < 3:
            raise Exception("Cannot parse thread and log type in {}".format(splits))
        # Parse log code
        if re.match(r'[0-9]+', splits[0]):
            self.thread = int(splits[0])
        else:
            raise Exception("Cannot parse thread in {}".format(splits[0]))
        if splits[1] in ['debug', 'info']:
            self.level = splits[1]
        else:
            raise Exception("Cannot parse log type in {}".format(splits[1]))
        self.msg = LogMsg().parse(':'.join(splits[2:]))
        return self

    def __str__(self):
        return TextColor.BOLD + TextColor.GRAY + datetime.utcfromtimestamp(self.date).strftime("%Y-%m-%d %H:%M:%S.%f%z") + TextColor.END + \
            ': ' + TextColor.BOLD + TextColor.GREEN + str(self.thread) + TextColor.END + \
            ': ' + self.msg.to_error_str()


class LogParser:
    def __init__(self):
        pass

    def parse(self, line, ind):
        return CommonLogItem().parse(line, ind)


class LogParserProcess(multiprocessing.Process):
    def __init__(self, logfile, start_id, end_id, results_queue, progress_queue):
        super(LogParserProcess, self).__init__()
        self.logfile = logfile
        self.start_id = start_id
        self.end_id = end_id
        self.results_queue = results_queue
        self.progress_queue = progress_queue
        self.logs = {
            '__datetime': [],
            '__line_index': [],
            '__thread': [],
        }
        self.parser = LogParser()

    @staticmethod
    def update_stats(logs, log):
        if log.msg.type not in logs:
            logs[log.msg.type] = {'lines_count': 0}
        if log.msg.error_contains:
            if 'error' not in logs[log.msg.type]:
                logs[log.msg.type]['error'] = log
                logs[log.msg.type]['error_lines'] = [log.line_index]
            else:
                logs[log.msg.type]['error_lines'].append(log.line_index)
        if log.msg.suspicious_level == 'Mismatch normal':
            if 'mismatch' not in logs[log.msg.type]:
                logs[log.msg.type]['mismatch'] = log
                logs[log.msg.type]['mismatch_lines'] = [log.line_index]
            else:
                logs[log.msg.type]['mismatch_lines'].append(log.line_index)
        logs[log.msg.type]['lines_count'] += 1
        logs['__datetime'].append(log.date)
        logs['__line_index'].append(log.line_index)
        logs['__thread'].append(log.thread)

    @staticmethod
    def merge_logs(log_a, log_b):
        for msg_type in log_b:
            if msg_type in ['__datetime', '__line_index', '__thread']:
                log_a[msg_type].extend(log_b[msg_type])
                continue
            if msg_type not in log_a:
                log_a[msg_type] = log_b[msg_type]
                continue
            log_a[msg_type]['lines_count'] += log_b[msg_type]['lines_count']
            if 'error_lines' in log_b[msg_type]:
                if 'error_lines' in log_a[msg_type]:
                    log_a[msg_type]['error_lines'].extend(log_b[msg_type]['error_lines'])
                else:
                    log_a[msg_type]['error_lines'] = log_b[msg_type]['error_lines']
            if 'mismatch_lines' in log_b[msg_type]:
                if 'mismatch_lines' in log_a[msg_type]:
                    log_a[msg_type]['mismatch_lines'].extend(log_b[msg_type]['mismatch_lines'])
                else:
                    log_a[msg_type]['mismatch_lines'] = log_b[msg_type]['mismatch_lines']
        return log_a

    def run(self):
        with open(self.logfile, "r") as logfile:
            (last_line, last_ind) = (None, None)
            last_progress = 0
            for i, line in enumerate(logfile.readlines()[self.start_id:self.end_id]):
                if i - last_progress >= 1000:
                    self.progress_queue.put(i - last_progress)
                    last_progress = i
                if TIME_REGEX.match(line[:28]):
                    if last_line is not None:
                        LogParserProcess.update_stats(self.logs, self.parser.parse(last_line, last_ind))
                        # self.results_queue.put(self.parser.parse(last_line, last_ind))
                    (last_line, last_ind) = (line, self.start_id + i + 1)
                else:
                    last_line += '\n' + line
            if last_line is not None:
                LogParserProcess.update_stats(self.logs, self.parser.parse(last_line, last_ind))
                # self.results_queue.put(self.parser.parse(last_line, last_ind))
            self.progress_queue.put(self.end_id - self.start_id - last_progress)
        self.progress_queue.put(None)
        self.results_queue.put(self.logs)


def describe(args, logs, df_datetime_analysis):
    # Errors #

    print(TextColor.BOLD + TextColor.PURPLE + '===================================' + TextColor.END)
    print(TextColor.BOLD + TextColor.PURPLE + 'Error like messages:' + TextColor.END)
    print(TextColor.BOLD + TextColor.PURPLE + '===================================' + TextColor.END)

    for msg_type in [key for key in sorted(logs.keys()) if 'error' in logs[key]]:
        print(
            'Message',
            TextColor.BOLD + TextColor.BLUE + repr(msg_type) + TextColor.END,
            ':'
        )
        print('Example', ':', logs[msg_type]['error'])
        print("Original line ids = [", end='')
        for i, line_index in enumerate(sorted(logs[msg_type]['error_lines'])):
            if i >= 5 and not args.full:
                print(end='...')
                break
            print(line_index, end=',')
        print(']')
    print()

    # Mismatch usual case #

    print(TextColor.BOLD + TextColor.PURPLE + '===================================' + TextColor.END)
    print(TextColor.BOLD + TextColor.PURPLE + 'Messages that mismatch usual case:' + TextColor.END)
    print(TextColor.BOLD + TextColor.PURPLE + '===================================' + TextColor.END)

    for msg_type in [key for key in sorted(logs.keys()) if 'mismatch' in logs[key]]:
        print(
            'Message',
            TextColor.BOLD + TextColor.BLUE + repr(msg_type) + TextColor.END,
            ':'
        )
        print('Example', ':', logs[msg_type]['mismatch'])
        print("Original line ids = [", end='')
        for i, line_index in enumerate(sorted(logs[msg_type]['mismatch_lines'])):
            if i >= 5 and not args.full:
                print(end='...')
                break
            print(line_index, end=',')
        print(']')
    print()

    # Unique messages #

    print(TextColor.BOLD + TextColor.PURPLE + '===================================' + TextColor.END)
    print(TextColor.BOLD + TextColor.PURPLE + 'Rare Messages:' + TextColor.END)
    print(TextColor.BOLD + TextColor.PURPLE + '===================================' + TextColor.END)

    logs_sorted = OrderedDict(sorted(logs.items(), key=lambda x: (x[1]['lines_count'], x[0])))
    line_counts = numpy.array([item['lines_count'] for _, item in logs_sorted.items()])
    line_masses = numpy.cumsum(line_counts / numpy.sum(line_counts))
    (printed_occurrences, printed_value) = (0, None)
    for msg_type, mass_val in zip(logs_sorted.keys(), line_masses.tolist()):
        if logs[msg_type]['lines_count'] != printed_value and mass_val > 0.001:
            break
        print(
            TextColor.BOLD + TextColor.BLUE + "{:<50}".format(repr(msg_type)) + TextColor.END,
            ':',
            "{:<3d},".format(logs[msg_type]['lines_count']),
            end=' '
        )
        printed_value = logs[msg_type]['lines_count']
        printed_occurrences += 1
        if printed_occurrences == 3:
            print()
            printed_occurrences = 0
    if printed_occurrences > 0:
        print()
    print()

    del logs
    del logs_sorted

    # Datetime analysis #

    print(TextColor.BOLD + TextColor.PURPLE + '===================================' + TextColor.END)
    print(TextColor.BOLD + TextColor.PURPLE + 'Slow log [per thread] line indices:' + TextColor.END)
    print(TextColor.BOLD + TextColor.PURPLE + '===================================' + TextColor.END)

    df_datetime_analysis.sort_values(['date', 'line_index'], inplace=True)
    quantiles = []
    for thread, thread_group in df_datetime_analysis.groupby('thread'):
        date_diff = numpy.diff(thread_group.date)
        quantiles.append(numpy.percentile(date_diff, 99))
    median_quantiles = numpy.median(numpy.nonzero(quantiles))
    min_quantiles = numpy.min(numpy.nonzero(quantiles))

    (greater_median_quantiles, greater_min_quantiles) = (0, 0)
    slow_logs, slow_logs_time = (None, None)
    for thread, thread_group in df_datetime_analysis.groupby('thread'):
        date_diff = numpy.diff(thread_group.date)
        slow_lines = thread_group.line_index[1:][date_diff > min_quantiles]
        slow_date_diff = date_diff[date_diff > min_quantiles]
        greater_median_quantiles += numpy.count_nonzero(date_diff > median_quantiles)
        greater_min_quantiles += numpy.count_nonzero(date_diff > min_quantiles)
        if slow_logs_time is None:
            slow_logs_time = slow_date_diff
            slow_logs = slow_lines
        else:
            slow_logs_time = numpy.concatenate([slow_logs_time, slow_date_diff])
            slow_logs = numpy.concatenate([slow_logs, slow_lines])

    df_datetime_analysis.sort_values(['thread', 'date', 'line_index'], inplace=True)
    line_indices = df_datetime_analysis.line_index.as_matrix()
    del df_datetime_analysis

    ids = numpy.argsort(slow_logs_time)[::-1]
    parser = LogParser()
    for i, (line_index, sec) in enumerate(zip(slow_logs[ids].tolist(), slow_logs_time[ids].tolist())):
        if i >= 10 and not args.full:
            print(end='...')
            break
        print(line_index, ':', TextColor.BOLD + "{:.2f}s".format(sec) + TextColor.END)

        prev_line_index_id = numpy.argwhere(line_indices == line_index)[0][0] - 1
        prev_line_index = line_indices[prev_line_index_id]

        with open(args.logfile, "r") as logfile:
            line_to_parse = None
            for line in logfile.readlines()[(prev_line_index - 1):]:
                if line_to_parse is None:
                    line_to_parse = line
                    continue
                if TIME_REGEX.match(line[:28]):
                    print("Previous line:", parser.parse(line_to_parse, prev_line_index))
                    break
                line_to_parse += '\n' + line

        with open(args.logfile, "r") as logfile:
            line_to_parse = None
            for line in logfile.readlines()[(line_index-1):]:
                if line_to_parse is None:
                    line_to_parse = line
                    continue
                if TIME_REGEX.match(line[:28]):
                    print("Current  line:", parser.parse(line_to_parse, line_index))
                    break
                line_to_parse += '\n' + line
    print()


def read_log(args):
    # Read log lines from file #
    # Merge multi-line logs (assume, that every log message starts from datetime string) #
    # Parse log messages [datetime, thread, level, msg]  #

    print('Parsing log messages ...', flush=True)

    logs = {
        '__datetime': [],
        '__line_index': [],
        '__thread': [],
    }

    with open(args.logfile, "r") as logfile:
        line_count = len(logfile.readlines())
    bar = ProgressBar(max_value=line_count)

    if args.n_jobs == 1:
        with open(args.logfile, "r") as logfile:
            (last_line, last_ind) = (None, None)
            parser = LogParser()
            for i, line in enumerate(logfile.readlines()):
                if TIME_REGEX.match(line[:28]):
                    if last_line is not None:
                        LogParserProcess.update_stats(logs, parser.parse(last_line, last_ind))
                    (last_line, last_ind) = (line, i + 1)
                else:
                    last_line += '\n' + line
                bar.update(i)
            if last_line is not None:
                LogParserProcess.update_stats(logs, parser.parse(last_line, last_ind))
    else:
        results_queue = multiprocessing.Queue()
        progress_queue = multiprocessing.Queue()
        workers = []

        # Spawn child processes #

        with open(args.logfile, "r") as logfile:
            lines = logfile.readlines()
            splits = [0]
            for i in range(args.n_jobs):
                splits.append(splits[i] + (line_count - splits[i]) // (args.n_jobs - i))
                while splits[i + 1] < line_count:
                    if TIME_REGEX.match(lines[splits[i + 1]][:28]):
                        break
                    splits[i + 1] += 1
                workers.append(LogParserProcess(args.logfile, splits[i], splits[i + 1], results_queue, progress_queue))
                workers[-1].start()

        # Collect data from child processes #

        n_jobs = len(workers)
        n = 0
        while n_jobs > 0:
            add_n = progress_queue.get()
            if add_n is None:
                n_jobs -= 1
                continue
            n += add_n
            bar.update(n)

        for i in range(len(workers)):
            log = results_queue.get()
            logs = LogParserProcess.merge_logs(logs, log)

        progress_queue.close()
        results_queue.close()

    bar.finish()
    print('Done')

    return logs


def main():
    # Handle command line argument #

    parser = argparse.ArgumentParser(description='Analyze log file')
    parser.add_argument('logfile', metavar='LOG_FILE', type=str, help='Log file to analyze')
    parser.add_argument('--n_jobs', type=int, help='Threading jobs for log parsing', default=1)
    parser.add_argument('--full', action='store_true', default=False, help='Request for full line_indices report')

    args = parser.parse_args()

    if not os.path.exists(args.logfile):
        raise Exception("{} doesn't exits".format(args.logfile))

    logs = read_log(args)

    # Store all data in pandas.DataFrame #

    print('Creating DataFrame ...')
    df_datetime_analysis = pd.DataFrame()
    df_datetime_analysis['line_index'] = [line_index for line_index in logs['__line_index']]
    logs.pop('__line_index', None)
    df_datetime_analysis['date'] = [date for date in logs['__datetime']]
    logs.pop('__datetime', None)
    df_datetime_analysis['thread'] = [thread for thread in logs['__thread']]
    logs.pop('__thread', None)
    print('Done')

    describe(args, logs, df_datetime_analysis)

if __name__ == "__main__":
    main()

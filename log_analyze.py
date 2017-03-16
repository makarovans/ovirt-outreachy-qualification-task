#!/usr/bin/env python
import os
import re
import numpy
import random
import pandas as pd
import threading
from datetime import datetime
import argparse
from progressbar import ProgressBar


class TextColor:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


class LogMsg:
    msg_type_normal_regex = {
        # info
        'virObjectRef': [
            re.compile(r'^virObjectRef:[0-9]+:OBJECT_REF:obj=0x[0-9a-f]+$'),
        ],
        'virObjectUnref': [
            re.compile(r'^virObjectUnref:[0-9]+:OBJECT_UNREF:obj=0x[0-9a-f]+$'),
            re.compile(r'^virObjectUnref:[0-9]+:OBJECT_DISPOSE:obj=0x[0-9a-f]+$'),
        ],
        'virObjectNew': [
            re.compile(r'^virObjectNew:[0-9]+:OBJECT_NEW:obj=0x[0-9a-f]+ classname=(vir|qemu)[A-Za-z]+$'),
        ],
        'qemuMonitorIOProcess': [
            re.compile(r'^qemuMonitorIOProcess:[0-9]+:QEMU_MONITOR_IO_PROCESS:mon=0x[0-9a-f]+ buf=.+(\n)*len=[0-9]+$'),
            re.compile(r'^qemuMonitorIOProcess:[0-9]+:QEMU_MONITOR_IO_PROCESS:mon=0x[0-9a-f]+ buf=(.+\n)+len=[0-9]+$'),
        ],
        'qemuMonitorIOWrite': [
            re.compile(r'^qemuMonitorIOWrite:[0-9]+:QEMU_MONITOR_IO_WRITE:mon=0x[0-9a-f]+ buf=.+\nlen=[0-9]+ ret=[0-9]+ errno=[0-9]+$'),
            re.compile(r'^qemuMonitorIOWrite:[0-9]+:QEMU_MONITOR_IO_SEND_FD:mon=0x[0-9a-f]+ fd=[0-9]+ ret=[0-9]+ errno=[0-9]+'),
        ],
        'qemuMonitorSend': [
            re.compile(r'^qemuMonitorSend:[0-9]+:QEMU_MONITOR_SEND_MSG:mon=0x[0-9a-f]+ msg={.+}\nfd=[\-0-9]'),
        ],
        'virFirewallApplyRule': [
            re.compile(r"^virFirewallApplyRule:[0-9]+:Applying rule '.*'$"),
        ],
        'virDBusCall': [
            re.compile(r"^virDBusCall:[0-9]+:DBUS_METHOD_CALL:'[a-zA-Z0-9\.]+' on '[a-zA-Z0-9/]+' at '[a-zA-Z0-9\.]+'$"),
            re.compile(r"^virDBusCall:[0-9]+:DBUS_METHOD_REPLY:'[a-zA-Z0-9\.]+' on '[a-zA-Z0-9/]+' at '[a-zA-Z0-9\.]+'$"),
        ],
        'virFirewallApplyGroup': [
            re.compile(r"^virFirewallApplyGroup:[0-9]+:Starting transaction for firewall=0x[0-9a-f]+ group=0x[0-9a-f]+ flags=[0-1]$"),
        ],
        'virSecuritySELinuxSetFileconHelper': [
            re.compile(r"^virSecuritySELinuxSetFileconHelper:[0-9]+:Setting SELinux context on '[a-zA-Z0-9\.\-/]+' to '[a-z_:0-9,]+'$"),
        ],
        'virSecurityDACSetOwnershipInternal': [
            re.compile(r"^virSecurityDACSetOwnershipInternal:[0-9]+:Setting DAC user and group on '[a-zA-Z0-9\.\-/]+' to '[:0-9]+'$"),
        ],
        'virNetDevProbeVnetHdr': [
            re.compile(r'^virNetDevProbeVnetHdr:[0-9]+:Enabling IFF_VNET_HDR$'),
        ],
        'qemuMonitorClose': [
            re.compile(r'^qemuMonitorClose:[0-9]+:QEMU_MONITOR_CLOSE:mon=0x[0-9a-f]+ refs=[0-9]+$'),
        ],
        'qemuMonitorOpenInternal': [
            re.compile(r'^qemuMonitorOpenInternal:[0-9]+:QEMU_MONITOR_NEW:mon=0x[0-9a-f]+ refs=[0-9]+ fd=[0-9]+$'),
        ],
        # debug
        'virAccessManagerCheckConnect': [
            re.compile(r'^virAccessManagerCheckConnect:[0-9]+:manager=0x[0-9a-f]+\(name=(stack|none)\) driver=QEMU perm=[0-9]+$'),
        ],
        'virAccessManagerCheckDomain': [
            re.compile(r'^virAccessManagerCheckDomain:[0-9]+:manager=0x[0-9a-f]+\(name=(stack|none)\) driver=QEMU domain=0x[0-9a-f]+ perm=[0-9]+$'),
        ],
        'virThreadJobClear': [
            re.compile(r'^virThreadJobClear:[0-9]+:Thread [0-9]+ \(virNetServerHandleJob\) finished job [a-zA-Z0-9]+ with ret=0$'),
        ],
        'virThreadJobSet': [
            re.compile(r'^virThreadJobSet:[0-9]+:Thread [0-9]+ \(virNetServerHandleJob\) is now running job [a-zA-Z0-9]+$'),
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
    ]

    def __init__(self):
        self.msg = None
        self.type = None
        self.suspicious_level = 'Mismatch normal'
        self.error_contains = False
        self.error_pos = []

    def parse(self, line):
        self.msg = line
        self.type = line.split(':')[0]
        if self.type not in LogMsg.msg_type_normal_regex:
            self.suspicious_level = 'Unknown message type'
        else:
            for regex in LogMsg.msg_type_normal_regex[self.type]:
                if regex.match(self.msg):
                    self.suspicious_level = 'Good'

        for error_regex in LogMsg.error_regex:
            if error_regex.search(self.msg):
                self.error_contains = True
                self.error_pos.extend([match for match in error_regex.finditer(self.msg)])
        return self

    def to_error_str(self):
        pos = 0
        result = ''
        for match in sorted(self.error_pos, key=lambda x: x.start()):
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
        # Set line index
        self.line_index = ind
        # Parse datetime
        try:
            self.date = datetime.strptime(line[:28], "%Y-%m-%d %H:%M:%S.%f%z")
            line = line[29:]
        except:
            raise Exception("Cannot parse datetime in {}".format(line))
        # Split log line
        splits = [item.strip() for item in line.split(':')]
        # Parse log code
        if self.date and len(splits) > 1:
            if re.match(r'[0-9]+', splits[0]):
                self.thread = splits[0]
                splits = splits[1:]
            else:
                raise Exception("Cannot parse thread in {}".format(splits[0]))
        if self.thread and len(splits) > 1:
            if splits[0] in ['debug', 'info']:
                self.level = splits[0]
                splits = splits[1:]
            else:
                raise Exception("Cannot parse log type in {}".format(splits[0]))
        self.msg = LogMsg().parse(':'.join(splits))
        return self


class LogParser:
    def __init__(self):
        pass

    def parse(self, line, ind):
        return CommonLogItem().parse(line, ind)


class LogStorage(object):
    def __init__(self, length):
        self.lock = threading.Lock()
        self.logs = []
        self.bar = ProgressBar(max_value=length)

    def update(self, log):
        self.lock.acquire()
        try:
            self.logs.extend(log)
            self.bar.update(len(self.logs))
        finally:
            self.lock.release()

    def get(self):
        return sorted(self.logs, key=lambda log: log.line_index)


class LogParserThread(threading.Thread):
    def __init__(self, raw_logs, log_storage):
        threading.Thread.__init__(self)
        self.raw_logs = raw_logs
        self.log_storage = log_storage
        self.parser = LogParser()

    def run(self):
        logs = [self.parser.parse(line, ind) for line, ind in self.raw_logs]
        self.log_storage.update(logs)


def describe(df):
    # Errors #
    print('Error like messages:')
    df_error = df[df.error_contains]
    for msg_type in df_error.drop_duplicates('msg_type').msg_type:
        print(
            'Message',
            TextColor.BOLD + TextColor.BLUE + repr(msg_type) + TextColor.END,
            ':'
        )
        df_error_msg_type = df_error[df_error.msg_type == msg_type]
        print('Example', ':', random.choice(df_error_msg_type.msg.tolist()).to_error_str())
        for thread in df_error_msg_type.drop_duplicates('thread').thread:
            print("Thread =", thread, "Original line ids = [", end='')
            for line_index in df_error_msg_type[df.thread == thread].line_index:
                print(line_index, end=',')
            print(']')
    # for thread in df.drop_duplicates('thread').thread:
    #     print('Thread', thread, ":")
    #     df_thread = df.query('thread == "{}"'.format(thread))
    #     # for dt, level, msg in zip(df_thread.date, df_thread.level, df_thread.msg):
    #     print(
    #         'cnt = ', df_thread.shape[0],
    #         'suspicious = ', df_thread.query("suspicious_level == 'Mismatch normal'").shape[0],
    #         'error_contains = ', df_thread.query("level == 'debug' and error_contains == True").shape[0]
    #     )


def main():
    # Handle command line argument #

    parser = argparse.ArgumentParser(description='Analyze log file')
    parser.add_argument('logfile', metavar='LOG_FILE', type=str, help='Log file to analyze')
    parser.add_argument('--n_jobs', type=int, help='Threading jobs for log parsing', default=1)

    args = parser.parse_args()

    if not os.path.exists(args.logfile):
        raise Exception("{} doesn't exits".format(args.logfile))

    # Read log lines from file #

    with open(args.logfile, "r") as logfile:
        log_lines = [line.strip() for line in logfile.readlines()]

    # Merge multi-line logs (assume, that every log message starts from datetime string) #

    print('Processing lines ...', flush=True)
    process_lines = []
    bar = ProgressBar(max_value=len(log_lines))
    for i, line in enumerate(log_lines):
        try:
            date = datetime.strptime(line[:28], "%Y-%m-%d %H:%M:%S.%f%z")
            process_lines.append((line, i + 1))
        except:
            process_lines[-1] = (process_lines[-1][0] + '\n' + line, process_lines[-1][1])
        bar.update(i)
    bar.finish()
    del log_lines

    # Parse log messages [datetime, thread, level, msg]  #

    print('Parsing log messages ...', flush=True)
    if args.n_jobs == 1:
        parser = LogParser()
        bar = ProgressBar(max_value=len(process_lines))
        logs = []
        for i, (line, ind) in enumerate(process_lines):
            logs.append(parser.parse(line, ind))
            bar.update(i)
        bar.finish()
    else:
        threads = []
        splits = [0]
        log_storage = LogStorage(len(process_lines))
        for i in range(args.n_jobs):
            splits.append(splits[i] + (len(process_lines) - splits[i]) // (args.n_jobs - i))
            threads.append(LogParserThread(process_lines[splits[i]:splits[i+1]], log_storage))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        logs = log_storage.get()
    del process_lines

    # Store all data in pandas.DataFrame #

    df = pd.DataFrame()
    df['line_index'] = [log.line_index for log in logs]
    df['date'] = [log.date for log in logs]
    df['thread'] = [log.thread for log in logs]
    df['level'] = [log.level for log in logs]
    df['msg'] = [log.msg for log in logs]
    df['msg_type'] = [log.msg.type for log in logs]
    df['suspicious_level'] = [log.msg.suspicious_level for log in logs]
    df['error_contains'] = [log.msg.error_contains for log in logs]
    del logs

    describe(df)

if __name__ == "__main__":
    main()

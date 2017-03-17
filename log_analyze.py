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
            re.compile(r"^virFirewallApplyRule:[0-9]+:Applying rule '.*(.*\n)*'$"),
            re.compile(r"^virFirewallApplyRule:[0-9]+:Invoking query 0x[0-9a-f]+ with '.*(.*\n)*'$"),
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
        'virDomainDispose': [
            re.compile(r'^virDomainDispose:[0-9]+:release domain 0x[0-9a-f]+ [a-zA-Z0-9]+ [a-f0-9\-]+$'),
        ],
        'virFileClose': [
            re.compile(r'^virFileClose:[0-9]+:Closed fd [1-9][0-9]*\n{0,1}\'{0,1}$'),
        ],
        'virCgroupGetValueStr': [
            re.compile(r'^virCgroupGetValueStr:[0-9]+:Get value [/\\a-zA-Z0-9,\-\._]+$'),
        ],
        'qemuDomainObjExitMonitorInternal': [
            re.compile(r'^qemuDomainObjExitMonitorInternal:[0-9]+:Exited monitor \(mon=0x[0-9a-f]+ vm=0x[0-9a-f]+ name=[a-zA-Z0-9]+\)$'),
        ],
        'qemuDomainObjEnterMonitorInternal': [
            re.compile(r'^qemuDomainObjEnterMonitorInternal:[0-9]+:Entering monitor \(mon=0x[0-9a-f]+ vm=0x[0-9a-f]+ name=[a-zA-Z0-9]+\)$'),
        ],
        'qemuMonitorBlockStatsUpdateCapacity': [
            re.compile(r'^qemuMonitorBlockStatsUpdateCapacity:[0-9]+:stats=0x[0-9a-f]+, backing=0$'),
            re.compile(r'^qemuMonitorBlockStatsUpdateCapacity:[0-9]+:mon:0x[0-9a-f]+ vm:0x[0-9a-f]+ json:1 fd:[1-9][0-9]*$'),
        ],
        'qemuMonitorGetAllBlockStatsInfo': [
            re.compile(r'^qemuMonitorGetAllBlockStatsInfo:[0-9]+:ret_stats=0x[0-9a-f]+, backing=0$'),
            re.compile(r'^qemuMonitorGetAllBlockStatsInfo:[0-9]+:mon:0x[0-9a-f]+ vm:0x[0-9a-f]+ json:1 fd:[1-9][0-9]*$'),
        ],
        'virConnectSupportsFeature': [
            re.compile(r'^virConnectSupportsFeature:[0-9]+:conn=0x[0-9a-f]+, feature=[0-9]+$'),
        ],
        'qemuMonitorGetBlockIoThrottle': [
            re.compile(r'^qemuMonitorGetBlockIoThrottle:[0-9]+:device=0x[0-9a-f]+, reply=0x[0-9a-f]+$'),
            re.compile(r'^qemuMonitorGetBlockIoThrottle:[0-9]+:mon:0x[0-9a-f]+ vm:0x[0-9a-f]+ json:1 fd:[1-9][0-9]*$'),
        ],
        'qemuGetProcessInfo': [
            re.compile(r'^qemuGetProcessInfo:[0-9]+:Got status for [0-9]+/[0-9]+ user=[0-9]+ sys=[0-9]+ cpu=[0-9]+ rss=[0-9]+$'),
        ],
        'virDomainFree': [
            re.compile(r'^virDomainFree:[0-9]+:dom=0x[0-9a-f]+, \(VM:name=[a-zA-Z0-9]+, uuid=[a-f0-9\-]+\)$'),
        ],
        'virDomainGetBlockIoTune': [
            re.compile(r'^virDomainGetBlockIoTune:[0-9]+:dom=0x[0-9a-f]+, \(VM:name=[a-zA-Z0-9]+, uuid=[a-f0-9\-]+\), disk=sda, params=(\(nil\)|0x[0-9a-f]+), nparams=[0-9]+, flags=[0-9]+$'),
        ],
        'virDomainGetMetadata': [
            re.compile(r'^virDomainGetMetadata:[0-9]+:dom=0x[0-9a-f]+, \(VM:name=[a-zA-Z0-9]+, uuid=[a-f0-9\-]+\), type=[0-9]+, uri=\'http://[a-z0-9\./]+\', flags=[0-9]+$'),
        ],
        'virNodeGetMemoryStats': [
            re.compile(r'^virNodeGetMemoryStats:[0-9]+:conn=0x[0-9a-f]+, cellNum=0, params=(\(nil\)|0x[0-9a-f]+), nparams=[0-9]+, flags=[0-9]+$'),
        ],
        'virConnectGetAllDomainStats': [
            re.compile(r'^virConnectGetAllDomainStats:[0-9]+:conn=0x[0-9a-f]+, stats=0x0, retStats=0x[0-9a-f]+, flags=0x0$'),
        ],
        'virDomainGetControlInfo': [
            re.compile(
                r'^virDomainGetControlInfo:[0-9]+:dom=0x[0-9a-f]+, \(VM:name=[a-zA-Z0-9]+, uuid=[a-f0-9\-]+\), info=0x[0-9a-f]+, flags=[0-9]+$'),
        ],
        'virNodeDeviceDispose': [
            re.compile(r'^virNodeDeviceDispose:[0-9]+:release dev 0x[0-9a-f]+ [a-zA-Z0-9_]+$'),
        ],
        'virCgroupDetect': [
            re.compile(r'^virCgroupDetect:[0-9]+:group=0x[0-9a-f]+ controllers=(-1|[0-9]+) path= parent=\(nil\)$'),
            re.compile(r'^virCgroupDetect:[0-9]+:Auto-detecting controllers$'),
            re.compile(r'^virCgroupDetect:[0-9]+:Controller \'(name=){0,1}[a-z_]+\' present=yes$'),
            re.compile(r'^virCgroupDetect:[0-9]+:Detected mount/mapping (0:cpu|1:cpuacct) at [/a-z,]+ in [0-9a-zA-Z\.\\/\-]+ for pid [0-9]+$'),
        ],
        'virAccessManagerCheckNodeDevice': [
            re.compile(r'^virAccessManagerCheckNodeDevice:[0-9]+:manager=0x[0-9a-f]+\(name=(stack|none)\) driver=QEMU nodedev=0x[0-9a-f]+ perm=[0-1]$'),
        ],
        'virNodeDeviceLookupByName': [
            re.compile(r'^virNodeDeviceLookupByName:[0-9]+:conn=0x[0-9a-f]+, name=[a-zA-Z0-9_]+$'),
        ],
        'virCgroupMakeGroup': [
            re.compile(r'^virCgroupMakeGroup:[0-9]+:Make group [/,a-zA-Z0-9\.\\\-_]+$'),
            re.compile(r'^virCgroupMakeGroup:[0-9]+:Make controller [/,a-zA-Z0-9\.\\\-_]+$'),
            re.compile(r'^virCgroupMakeGroup:[0-9]+:Done making controllers for group$'),
        ],
        'virCommandRunAsync': [
            re.compile(r'^virCommandRunAsync:[0-9]+:About to run .+$'),
            re.compile(r'^virCommandRunAsync:[0-9]+:Command result 0, with PID [0-9]+$'),
        ],
        'virCommandRun': [
            re.compile(r'^virCommandRun:[0-9]+:Result (exit ){0,1}status 0, stdout:\'.*\' stderr:\'.*(\'){0,1}$', re.DOTALL),
        ],
        'virNodeDeviceGetXMLDesc': [
            re.compile(r'^virNodeDeviceGetXMLDesc:[0-9]+:dev=0x[0-9a-f]+, conn=0x[0-9a-f]+, flags=[0-9]+$'),
        ],
        'virDomainGetInfo': [
            re.compile(r'^virDomainGetInfo:[0-9]+:dom=0x[0-9a-f]+, \(VM:name=[a-zA-Z0-9]+, uuid=[a-f0-9\-]+\), info=0x[0-9a-f]+$'),
        ],
        'virNodeGetCPUMap': [
            re.compile(r'^virNodeGetCPUMap:[0-9]+:conn=0x[0-9a-f]+, cpumap=\(nil\), online=\(nil\), flags=0$'),
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
        self.length = length
        self.bar = ProgressBar(max_value=length)

    def update(self, log):
        self.lock.acquire()
        try:
            self.logs.extend(log)
            self.bar.update(len(self.logs))
            if len(self.logs) == self.length:
                self.bar.finish()
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

    print(TextColor.BOLD, 'Error like messages:', TextColor.END)
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
            for line_index in df_error_msg_type[df_error_msg_type.thread == thread].line_index:
                print(line_index, end=',')
            print(']')

    # Mismatch usual case #

    print(TextColor.BOLD, 'Messages that mismatch usual case:', TextColor.END)
    df_unusual = df.query("suspicious_level == 'Mismatch normal' and error_contains == False")
    for msg_type in df_unusual.drop_duplicates('msg_type').msg_type:
        print(
            'Message',
            TextColor.BOLD + TextColor.BLUE + repr(msg_type) + TextColor.END,
            ':'
        )
        df_unusual_msg_type = df_unusual[df_unusual.msg_type == msg_type]
        print('Example', ':', random.choice(df_unusual_msg_type.msg.tolist()).to_error_str())
        for thread in df_unusual_msg_type.drop_duplicates('thread').thread:
            print("Thread =", thread, "Original line ids = [", end='')
            for line_index in df_unusual_msg_type[df_unusual_msg_type.thread == thread].line_index:
                print(line_index, end=',')
            print(']')

    # Unique messages #

    # Datetime analysis #

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
        del log_storage
    del process_lines

    # Store all data in pandas.DataFrame #

    print('Creating DataFrame ...')
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
    print('Done')

    describe(df)

if __name__ == "__main__":
    main()

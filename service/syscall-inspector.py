#!/usr/bin/python3

import sqlite3
import signal
import sys
import os
import syslog
import configparser
import time
import json
import fnmatch
from datetime import datetime, timedelta
from bcc import BPF

DB_PATH = "/var/lib/syscall-inspector/data.db"
DB_DIR = os.path.dirname(DB_PATH)
CONFIG_PATH = "/etc/syscall-inspector/config.conf"
RULES_PATH = "/etc/syscall-inspector/rules.json"

SEVERITY_MAP = {
    "critical": "Критический",
    "high": "Высокий",
    "medium": "Средний",
    "low": "Низкий",
    "info": "Инфо"
}

bpf_program = """
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 type;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char fname[256];
};

BPF_PERF_OUTPUT(events);

static void fill_data(struct data_t *data, u32 type) {
    struct task_struct *task;
    struct task_struct *parent;

    task = (struct task_struct *)bpf_get_current_task();
    parent = task->real_parent;

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->ppid = parent->pid;
    data->type = type;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_probe_read_kernel(&data->pcomm, sizeof(data->pcomm), parent->comm);
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    fill_data(&data, 1);
    bpf_probe_read_user(data.fname, sizeof(data.fname), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    fill_data(&data, 2);
    bpf_probe_read_user(data.fname, sizeof(data.fname), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

class RuleEngine:
    def __init__(self, rules_path=RULES_PATH):
        self.rules_path = rules_path
        self.rules = {}
        self.reload_rules()

    def _load_default_rules(self):
        return {
            "ignore_extensions": [".png", ".jpg", ".so", ".pyc", ".swp"],
            "global_ignore_processes": ["syscall-inspect"],
            "filters": {
                "process_execution": {
                    "mode": "exclude", 
                    "excludes": [], 
                    "rules": [{"pattern": "*", "severity": "medium"}]
                },
                "sensitive_file_access": {
                    "mode": "exclude", 
                    "excludes": [], 
                    "rules": [{"pattern": "*", "severity": "medium"}]
                }
            }
        }

    def reload_rules(self):
        if os.path.exists(self.rules_path):
            try:
                with open(self.rules_path, 'r') as f:
                    self.rules = json.load(f)
            except Exception:
                self.rules = self._load_default_rules()
        else:
            self.rules = self._load_default_rules()

    def is_process_ignored(self, comm):
        return comm in self.rules.get("global_ignore_processes", [])

    def is_extension_ignored(self, filename):
        exts = tuple(self.rules.get("ignore_extensions", []))
        if not exts:
            return False
        return filename.endswith(exts)

    def _check_list(self, value, pattern_list):
        for pattern in pattern_list:
            if fnmatch.fnmatch(value, pattern):
                return True
        return False

    def evaluate(self, event_category, value):
        config = self.rules.get("filters", {}).get(event_category, {})
        excludes = config.get("excludes", [])
        
        if self._check_list(value, excludes):
            return False, None

        defined_rules = config.get("rules", [])
        matched_severity = "medium"
        has_match = False

        for rule in defined_rules:
            pattern = rule.get("pattern")
            if fnmatch.fnmatch(value, pattern):
                matched_severity = rule.get("severity", "medium")
                has_match = True
                break
        
        mode = config.get("mode", "exclude")

        if mode == "include":
            return has_match, matched_severity
        else:
            return True, matched_severity

class SyscallDaemon:
    def __init__(self):
        self.running = True
        self.conn = None
        self.bpf = None
        self.siem_enabled = True
        self.log_format = "rfc3164"
        self.retention_days = 30
        self.my_pid = os.getpid()
        self.dedup_cache = {}
        self.rule_engine = RuleEngine()

        syslog.openlog(ident="syscall-ebpf", logoption=syslog.LOG_PID, facility=syslog.LOG_USER)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGHUP, self.reload_handler)

    def signal_handler(self, sig, frame):
        self.running = False

    def reload_handler(self, sig, frame):
        self.load_config()
        self.rule_engine.reload_rules()
        self.cleanup_logs()

    def load_config(self):
        try:
            config = configparser.ConfigParser()
            if os.path.exists(CONFIG_PATH):
                config.read(CONFIG_PATH)
                if 'General' in config:
                    self.siem_enabled = config['General'].getboolean('siem_enabled', fallback=True)
                    self.log_format = config['General'].get('log_format', 'rfc3164')
                    self.retention_days = config['General'].getint('retention_days', fallback=30)
        except Exception:
            self.siem_enabled = True
            self.log_format = "rfc3164"
            self.retention_days = 30

    def init_storage(self):
        try:
            os.makedirs(DB_DIR, exist_ok=True)
            self.conn = sqlite3.connect(DB_PATH, timeout=5)
            os.chmod(DB_PATH, 0o644)
            cursor = self.conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    severity TEXT,
                    event_type TEXT,
                    process TEXT,
                    pid INTEGER,
                    details TEXT
                )
            ''')
            self.conn.commit()
        except Exception:
            sys.exit(1)

    def cleanup_logs(self):
        """Удаляет логи старше self.retention_days дней"""
        if not self.conn:
            return
            
        try:
            cutoff_date = (datetime.now() - timedelta(days=self.retention_days)).isoformat()
            cursor = self.conn.cursor()
            
            cursor.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff_date,))
            deleted_count = cursor.rowcount
            
            if deleted_count > 0:
                self.conn.commit()
                cursor.execute("VACUUM")
                syslog.syslog(syslog.LOG_INFO, f"Log rotation: deleted {deleted_count} alerts older than {self.retention_days} days.")
            
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, f"Log rotation failed: {e}")

    def should_log(self, pid, event_type, details):
        current_time = time.time()
        if len(self.dedup_cache) > 1000:
            self.dedup_cache.clear()

        key = (pid, event_type, details)
        last_time = self.dedup_cache.get(key)

        if last_time and (current_time - last_time < 2.0):
            return False
        
        self.dedup_cache[key] = current_time
        return True

    def send_syslog(self, severity_code, event_type, process, pid, ppid, details):
        priority = syslog.LOG_INFO
        if severity_code == "critical": priority = syslog.LOG_CRIT
        elif severity_code == "high": priority = syslog.LOG_ALERT
        elif severity_code == "medium": priority = syslog.LOG_WARNING
        elif severity_code == "low": priority = syslog.LOG_NOTICE

        msg = ""
        if self.log_format == "json":
            log_dict = {
                "event_type": event_type,
                "process": process,
                "pid": pid,
                "ppid": ppid,
                "details": details,
                "severity": severity_code, 
                "timestamp": datetime.now().isoformat()
            }
            msg = json.dumps(log_dict)
        elif self.log_format == "cef":
            sev_num = 5
            if severity_code == "critical": sev_num = 10
            elif severity_code == "high": sev_num = 8
            msg = f"CEF:0|AltLinux|SyscallInspector|1.0|{event_type}|{event_type}|{sev_num}|src=127.0.0.1 proc={process} pid={pid} msg={details}"
        else: 
            msg = f"WAZUH_EVENT: {event_type} | SEVERITY: {severity_code} | PROCESS: {process} | PID: {pid} | DETAILS: {details}"

        syslog.syslog(priority, msg)

    def log_event(self, severity_code, event_type, process, pid, ppid, pcomm, details):
        if not self.should_log(pid, event_type, details):
            return

        timestamp = datetime.now().isoformat()
        enriched_details = f"{details} [Parent: {pcomm} ({ppid})]"

        if self.siem_enabled:
            self.send_syslog(severity_code, event_type, process, pid, ppid, details)

        severity_ru = SEVERITY_MAP.get(severity_code, severity_code)

        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO alerts (timestamp, severity, event_type, process, pid, details) VALUES (?, ?, ?, ?, ?, ?)",
                (timestamp, severity_ru, event_type, process, pid, enriched_details)
            )
            self.conn.commit()
        except Exception:
            pass

    def process_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        
        if event.pid == self.my_pid or event.ppid == self.my_pid:
            return

        comm = event.comm.decode('utf-8', 'replace').strip()
        
        if self.rule_engine.is_process_ignored(comm):
            return
            
        fname = event.fname.decode('utf-8', 'replace')
        pcomm = event.pcomm.decode('utf-8', 'replace')

        if self.rule_engine.is_extension_ignored(fname):
            return
        
        if event.type == 1:
            target_proc = fname if fname else comm
            alert, severity = self.rule_engine.evaluate("process_execution", target_proc)
            if alert:
                self.log_event(severity, "process_execution", comm, event.pid, event.ppid, pcomm, f"Запуск команды: {fname}")
            
        elif event.type == 2:
            alert, severity = self.rule_engine.evaluate("sensitive_file_access", fname)
            if alert:
                self.log_event(severity, "sensitive_file_access", comm, event.pid, event.ppid, pcomm, f"Доступ к файлу: {fname}")

    def run(self):
        self.init_storage()
        self.load_config()
        self.cleanup_logs()

        try:
            self.bpf = BPF(text=bpf_program)
        except Exception:
            sys.exit(1)

        self.bpf["events"].open_perf_buffer(self.process_event)
        
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
            except Exception:
                pass
        
        if self.conn:
            self.conn.close()

if __name__ == "__main__":
    SyscallDaemon().run()

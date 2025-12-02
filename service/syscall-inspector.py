#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sqlite3
import signal
import sys
import os
import time
import syslog
from bcc import BPF

DB_PATH = "/var/lib/syscall-inspector/data.db"
DB_DIR = os.path.dirname(DB_PATH)
FILTER_PATH = "/var/lib/syscall-inspector/filter.conf"

SYSCALL_MAP = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat", 
    6: "lstat", 7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect", 
    11: "munmap", 12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask", 
    16: "ioctl", 17: "pread64", 18: "pwrite64", 19: "readv", 20: "writev", 
    21: "access", 22: "pipe", 23: "select", 24: "sched_yield", 
    39: "getpid", 41: "socket", 42: "connect", 43: "accept", 
    44: "sendto", 45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 
    48: "shutdown", 49: "bind", 50: "listen", 56: "clone", 57: "fork", 59: "execve", 
    61: "wait4", 62: "kill", 72: "fcntl", 78: "getdents", 79: "getcwd", 80: "chdir", 
    82: "rename", 83: "mkdir", 84: "rmdir", 87: "unlink", 88: "symlink", 89: "readlink",
    90: "chmod", 91: "fchmod", 92: "chown", 93: "fchown", 95: "umask", 
    102: "getuid", 104: "getgid", 107: "geteuid", 108: "getegid", 
    217: "getdents64", 231: "exit_group", 257: "openat", 
    254: "epoll_ctl", 262: "newfstatat", 
    270: "pselect6", 271: "ppoll", 281: "epoll_pwait", 302: "renameat2", 334: "rseq"
}

SIEM_INTERESTING_SYSCALLS = [
    "execve",
    "connect",
    "accept",
    "bind",
    "ptrace",
    "chmod", "fchmod",
    "chown", "fchown",
    "unlink",
    "rename", "renameat2",
    "mkdir", "rmdir",
    "symlink"
]

bpf_program_template = """
#include <linux/sched.h>

struct data_t {{
    u32 pid;
    char comm[TASK_COMM_LEN];
    unsigned long syscall_nr;
}};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {{
    struct data_t data = {{}};
    char comm[TASK_COMM_LEN]; 
    bpf_get_current_comm(&comm, sizeof(comm));

    {filter_check}

    data.pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(data.comm, comm, TASK_COMM_LEN); 
    data.syscall_nr = args->id;

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}}
"""

class SyscallDaemon:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
        self.bpf = None
        self.buffer = {} 
        self.last_flush = time.time()
        self.running = True
        
        syslog.openlog(ident="syscall-ebpf", logoption=syslog.LOG_PID, facility=syslog.LOG_AUTHPRIV)
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.running = False
        self.flush_buffer()
        self.stop()
        sys.exit(0)

    def init_db(self):
        try:
            os.makedirs(DB_DIR, exist_ok=True)
            self.conn = sqlite3.connect(self.db_path, timeout=5)
            os.chmod(self.db_path, 0o644)
            cursor = self.conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS syscalls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    pid INTEGER,
                    comm TEXT,
                    syscall_name TEXT, 
                    count INTEGER DEFAULT 1
                )
            ''')
            self.conn.commit()
        except Exception as e:
            print(f"Ошибка инициализации БД: {e}", file=sys.stderr)
            sys.exit(1)

    def get_watched_processes(self):
        watched = set()
        if os.path.exists(FILTER_PATH):
            try:
                with open(FILTER_PATH, 'r') as f:
                    for line in f:
                        proc = line.strip()
                        proc = "".join(x for x in proc if x.isalnum() or x in "._-")
                        if proc:
                            watched.add(proc)
            except:
                pass
        return watched

    def process_event(self, cpu, data, size):
        if not self.running:
            return
            
        event = self.bpf["events"].event(data)
        nr = event.syscall_nr
        name = SYSCALL_MAP.get(nr, str(nr))
        
        key = (event.pid, event.comm.decode('utf-8', 'replace'), name)
        
        if key in self.buffer:
            self.buffer[key] += 1
        else:
            self.buffer[key] = 1

        if time.time() - self.last_flush > 1.0:
            self.flush_buffer()

    def flush_buffer(self):
        if not self.buffer:
            return

        watched_procs = self.get_watched_processes()

        try:
            if not self.conn:
                self.conn = sqlite3.connect(self.db_path, timeout=5)

            cursor = self.conn.cursor()
            
            for (pid, comm, name), count in self.buffer.items():
                cursor.execute(
                    "INSERT INTO syscalls (pid, comm, syscall_name, count) VALUES (?, ?, ?, ?)",
                    (pid, comm, name, count)
                )

                if comm in watched_procs:
                    if name in SIEM_INTERESTING_SYSCALLS:
                        priority = syslog.LOG_NOTICE
                        if name in ["execve", "ptrace", "renameat2"]:
                            priority = syslog.LOG_WARNING
                        
                        msg = f"SIEM_EVENT: Process '{comm}' (PID {pid}) called '{name}' {count} times"
                        syslog.syslog(priority, msg)

            self.conn.commit()
            self.buffer.clear()
            self.last_flush = time.time()
            
        except sqlite3.ProgrammingError:
            pass
        except Exception as e:
            if "closed" not in str(e).lower():
                print(f"Ошибка записи: {e}", file=sys.stderr)

    def run(self):
        self.init_db()
        bpf_text = bpf_program_template.format(filter_check="")
        
        try:
            self.bpf = BPF(text=bpf_text)
        except Exception as e:
            print(f"Ошибка загрузки eBPF: {e}", file=sys.stderr)
            sys.exit(1)
            
        self.bpf["events"].open_perf_buffer(self.process_event)
        print("Service started. Strict SIEM mode active.", file=sys.stderr)
        
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=500)
                if time.time() - self.last_flush > 1.0:
                    self.flush_buffer()
            except KeyboardInterrupt:
                break
            except Exception:
                pass
        
        self.stop()

    def stop(self):
        self.running = False
        if self.conn:
            try:
                self.conn.close()
            except:
                pass
            self.conn = None

if __name__ == "__main__":
    SyscallDaemon(DB_PATH).run()

#!/usr/bin/env python3

import re
import subprocess
import sys
import signal
import ctypes as ct
import os
import time
from bcc import BPF


class IOCTLTracer:
    """BPF-based tracer for ioctl, sendmsg, and recvmsg syscalls."""

    # Mapping of relevant ioctl command values to their symbolic names
    IOCTL_NAMES = {
        0xc0186443: "DRM_IOCTL_AMDGPU_BO_LIST",
        0xc0186444: "DRM_IOCTL_AMDGPU_CS",
        0xc0106442: "DRM_IOCTL_AMDGPU_CTX",
        0xc0206454: "DRM_IOCTL_AMDGPU_FENCE_TO_HANDLE",
        0xc0206440: "DRM_IOCTL_AMDGPU_GEM_CREATE",
        0xc1206446: "DRM_IOCTL_AMDGPU_GEM_METADATA",
        0xc0086441: "DRM_IOCTL_AMDGPU_GEM_MMAP",
        0xc0106450: "DRM_IOCTL_AMDGPU_GEM_OP",
        0xc0186451: "DRM_IOCTL_AMDGPU_GEM_USERPTR",
        0x40286448: "DRM_IOCTL_AMDGPU_GEM_VA",
        0xc0106447: "DRM_IOCTL_AMDGPU_GEM_WAIT_IDLE",
        0x40206445: "DRM_IOCTL_AMDGPU_INFO",
        0x40106455: "DRM_IOCTL_AMDGPU_SCHED",
        0xc0086453: "DRM_IOCTL_AMDGPU_VM",
        0xc0206449: "DRM_IOCTL_AMDGPU_WAIT_CS",
        0xc0186452: "DRM_IOCTL_AMDGPU_WAIT_FENCES",
        0xc00864bf: "DRM_IOCTL_SYNCOBJ_CREATE",
        0xc00864c0: "DRM_IOCTL_SYNCOBJ_DESTROY",
        0xc01864cf: "DRM_IOCTL_SYNCOBJ_EVENTFD",
        0xc01064c2: "DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE",
        0xc01064c1: "DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD",
        0xc01864cb: "DRM_IOCTL_SYNCOBJ_QUERY",
        0xc01064c4: "DRM_IOCTL_SYNCOBJ_RESET",
        0xc01064c5: "DRM_IOCTL_SYNCOBJ_SIGNAL",
        0xc01864cd: "DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL",
        0xc03064ca: "DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT",
        0xc02064cc: "DRM_IOCTL_SYNCOBJ_TRANSFER",
        0xc02864c3: "DRM_IOCTL_SYNCOBJ_WAIT",
    }

    COLORS = {
        'RESET': "\033[0m",
        'BOLD': "\033[1m",
        'CYAN': "\033[36m",
        'YELLOW': "\033[33m",
        'GREEN': "\033[32m",
        'MAGENTA': "\033[35m",
        'BLUE': "\033[34m",
        'RED': "\033[31m",
        'GRAY': "\033[90m",
    }

    BPF_PROGRAM = """
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>

    struct data_t {
        u32 pid;
        u32 tid;
        u64 fd;
        u64 cmd;
        u64 arg;
        int user_stack_id;
        int kernel_stack_id;
        char comm[TASK_COMM_LEN];
        u8 event_type;
    };

    BPF_PERF_OUTPUT(events);
    BPF_STACK_TRACE(stack_traces, 1024);

    int trace_ioctl(struct tracepoint__syscalls__sys_enter_ioctl *args) {
        struct data_t data = {};
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 tid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.pid = pid;
        data.tid = tid;
        data.fd = args->fd;
        data.cmd = args->cmd;
        data.arg = args->arg;
        data.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
        data.kernel_stack_id = stack_traces.get_stackid(args, 0);
        data.event_type = 0;
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }

    int trace_amdgpu_ioctl(struct pt_regs *ctx) {
        struct data_t data = {};
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 tid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.pid = pid;
        data.tid = tid;
        data.fd = 0;
        data.cmd = PT_REGS_PARM2(ctx);
        data.arg = PT_REGS_PARM3(ctx);
        data.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
        data.kernel_stack_id = stack_traces.get_stackid(ctx, 0);
        data.event_type = 1;
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }

    int trace_recvmsg(struct tracepoint__syscalls__sys_enter_recvmsg *args) {
        struct data_t data = {};
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 tid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.pid = pid;
        data.tid = tid;
        data.fd = args->fd;
        data.cmd = 0;
        data.arg = (u64)args->msg;
        data.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
        data.kernel_stack_id = -1;
        data.event_type = 2;
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }

    int trace_sendmsg(struct tracepoint__syscalls__sys_enter_sendmsg *args) {
        struct data_t data = {};
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 tid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.pid = pid;
        data.tid = tid;
        data.fd = args->fd;
        data.cmd = 0;
        data.arg = (u64)args->msg;
        data.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
        data.kernel_stack_id = -1;
        data.event_type = 3;
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }
    """

    def __init__(self, binary_path, cpp_file_path, target_comm):
        self.binary_path = binary_path
        self.cpp_file_path = cpp_file_path
        self.target_comm = target_comm
        self.shutdown_requested = False
        self.user_events = {}
        self.fd_map = {}
        self.cpp_stack_pattern = re.compile(
            r'^(HelloTriangleApplication::[^\(]+)\(\)\+0x([0-9a-fA-F]+)$')

        self._map_file_descriptors()

        # Initialize BPF
        self.bpf = BPF(text=self.BPF_PROGRAM)
        self._setup_tracing()
        self._setup_signal_handler()

    def _find_pids_by_name(self, proc_name):
        """Find PIDs by process name."""
        pids = []
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    with open(f"/proc/{pid}/comm", "r") as f:
                        name = f.read().strip()
                        if name == proc_name:
                            pids.append(pid)
                except Exception:
                    continue
        return pids

    def _map_file_descriptors(self):
        """Map file descriptors for the target process."""
        print(f"Mapping file descriptors for {self.target_comm}...")

        pids = self._find_pids_by_name(self.target_comm)
        if not pids:
            print(f"Warning: No process found with name '{self.target_comm}'.")
            return

        if len(pids) > 1:
            print(f"Multiple processes found with name '{self.target_comm}':")
            for i, pid in enumerate(pids):
                print(f"{i+1}: PID {pid}")
            try:
                choice = int(
                    input("Select the process number to inspect: ")) - 1
                if not (0 <= choice < len(pids)):
                    raise ValueError
                pid = pids[choice]
            except Exception:
                print("Invalid selection.")
                sys.exit(1)
        else:
            pid = pids[0]

        fd_dir = f"/proc/{pid}/fd"
        if not os.path.isdir(fd_dir):
            print(f"Warning: {fd_dir} does not exist or is not a directory.")
            return

        unique_fds = {}
        start = time.time()
        duration = 5.0
        interval = 0.01

        try:
            while time.time() - start < duration:
                try:
                    for fd in os.listdir(fd_dir):
                        fd_path = os.path.join(fd_dir, fd)
                        try:
                            target = os.readlink(fd_path)
                            unique_fds[fd] = target
                        except Exception:
                            pass
                except Exception:
                    pass
                time.sleep(interval)
        except KeyboardInterrupt:
            pass

        self.fd_map = {int(fd): target for fd, target in unique_fds.items()}
        print(f"Mapped {len(self.fd_map)} file descriptors.")

    def _setup_tracing(self):
        """Set up BPF tracing points."""
        self.bpf.attach_tracepoint(tp="syscalls:sys_enter_ioctl",
                                   fn_name="trace_ioctl")
        self.bpf.attach_kprobe(event="amdgpu_drm_ioctl",
                               fn_name="trace_amdgpu_ioctl")
        self.bpf.attach_tracepoint(tp="syscalls:sys_enter_recvmsg",
                                   fn_name="trace_recvmsg")
        self.bpf.attach_tracepoint(tp="syscalls:sys_enter_sendmsg",
                                   fn_name="trace_sendmsg")

    def _setup_signal_handler(self):
        """Set up signal handler for graceful shutdown."""
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signal."""
        print("\nShutdown requested...")
        self.shutdown_requested = True

    def color(self, text, *colors):
        """Apply color(s) to text."""
        color_codes = ''.join(self.COLORS[c] for c in colors)
        return f"{color_codes}{text}{self.COLORS['RESET']}"

    @staticmethod
    def decode_ioctl(cmd):
        """Decode ioctl command into its components."""
        IOC_NRBITS = 8
        IOC_TYPEBITS = 8
        IOC_SIZEBITS = 14
        IOC_DIRBITS = 2

        IOC_NRSHIFT = 0
        IOC_TYPESHIFT = IOC_NRSHIFT + IOC_NRBITS
        IOC_SIZESHIFT = IOC_TYPESHIFT + IOC_TYPEBITS
        IOC_DIRSHIFT = IOC_SIZESHIFT + IOC_SIZEBITS

        IOC_DIRMASK = (1 << IOC_DIRBITS) - 1
        IOC_TYPEMASK = (1 << IOC_TYPEBITS) - 1
        IOC_NRMASK = (1 << IOC_NRBITS) - 1
        IOC_SIZEMASK = (1 << IOC_SIZEBITS) - 1

        dir_val = (cmd >> IOC_DIRSHIFT) & IOC_DIRMASK
        typ = (cmd >> IOC_TYPESHIFT) & IOC_TYPEMASK
        nr = (cmd >> IOC_NRSHIFT) & IOC_NRMASK
        size = (cmd >> IOC_SIZESHIFT) & IOC_SIZEMASK

        dir_str = {
            0: "NONE",
            1: "WRITE",
            2: "READ",
            3: "READ/WRITE"
        }.get(dir_val, "UNKNOWN")

        try:
            type_chr = chr(typ) if 32 <= typ < 127 else f"0x{typ:x}"
        except:
            type_chr = f"0x{typ:x}"

        return f"type={type_chr} nr=0x{nr:x} dir={dir_str} size={size}"

    def get_function_address(self, function):
        """Get function address from binary using nm."""
        result = subprocess.run(["nm", "-C", self.binary_path],
                                stdout=subprocess.PIPE,
                                text=True)
        for line in result.stdout.splitlines():
            if function in line:
                addr = line.split()[0]
                return int(addr, 16)
        return None

    def addr2line(self, address):
        """Get source line from address using addr2line."""
        result = subprocess.run(
            ["addr2line", "-e", self.binary_path,
             hex(address)],
            stdout=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()

    def get_source_line(self, line_number):
        """Get source code line from file."""
        try:
            with open(self.cpp_file_path, 'r') as f:
                lines = f.readlines()
                if 1 <= line_number <= len(lines):
                    return lines[line_number - 1].rstrip()
                else:
                    return f"<line {line_number} out of range>"
        except Exception as e:
            return f"<error reading {self.cpp_file_path}: {e}>"

    def print_stack(self,
                    frames,
                    resolve_fn,
                    color_stack,
                    color_unknown,
                    pid=None):
        """Print stack trace with source code resolution."""
        unknown_count = 0

        for addr in frames:
            sym = resolve_fn(addr)
            if isinstance(sym, bytes):
                sym = sym.decode(errors="replace")

            # Check if this frame is unknown
            is_unknown = sym == "[unknown]" or sym == "b'[unknown]'"

            if is_unknown:
                unknown_count += 1
                continue

            # This is a known frame - first flush any accumulated unknowns
            if unknown_count > 0:
                print(
                    f"    {self.color(f'unknown (x{unknown_count})', color_unknown)}"
                )
                unknown_count = 0

            # Try to resolve C++ source lines
            match = self.cpp_stack_pattern.match(sym)
            if match:
                function = match.group(1) + "()"
                offset = int(match.group(2), 16)
                func_addr = self.get_function_address(function)
                if func_addr is not None:
                    abs_addr = func_addr + offset
                    src_line = self.addr2line(abs_addr)
                    src_path_line = src_line.split(' ')[0]
                    if ':' in src_path_line:
                        _, line_num_str = src_path_line.rsplit(':', 1)
                        try:
                            line_num = int(line_num_str)
                        except ValueError:
                            line_num = None
                        if line_num:
                            code_line = self.get_source_line(line_num).lstrip()
                            code_line_prev = self.get_source_line(line_num -
                                                                  1).lstrip()
                            if "if" in code_line_prev:
                                print(
                                    f"    {self.color(f'<src:{line_num-1}>', 'YELLOW')}\t"
                                    f"{self.color(code_line_prev, 'YELLOW')}")
                                print(
                                    f"        {self.color(f'--->{line_num_str}>', 'YELLOW')}\t"
                                    f"{self.color(code_line, 'YELLOW')}")
                            elif "vkAcquireNextImageKHR" in code_line_prev:
                                print(
                                    f"    {self.color(f'<src:{line_num-1}>', 'YELLOW')}\t"
                                    f"{self.color(code_line_prev, 'YELLOW')}")
                                print(
                                    f"        {self.color(f'--->{line_num_str}>', 'YELLOW')}\t"
                                    f"{self.color(code_line, 'YELLOW')}")
                            else:
                                print(
                                    f"    {self.color(f'<src:{line_num_str}>', color_stack)}\t"
                                    f"{self.color(code_line, color_stack)}")
                            continue

            # Print the known frame
            print(f"    {self.color(sym, color_stack)}")

        # Don't forget to flush any remaining unknowns at the end
        if unknown_count > 0:
            print(
                f"    {self.color(f'unknown (x{unknown_count})', color_unknown)}"
            )

    def format_fd_info(self, fd):
        """Format file descriptor with target information."""
        fd_target = self.fd_map.get(fd, "unknown")
        return f"{fd} ({self.color(fd_target, 'YELLOW')})"

    def print_full_event(self, user, kernel):
        """Print complete event information."""
        syscall_name = {
            0: "ioctl",
            1: "ioctl (kernel)",
            2: "recvmsg",
            3: "sendmsg"
        }.get(user.event_type, "unknown")

        name = self.IOCTL_NAMES.get(user.cmd,
                                    "UNKNOWN") if user.event_type == 0 else ""

        print(
            self.color(f"=== {syscall_name.upper()} EVENT ===", 'BOLD',
                       'MAGENTA'))
        print(
            f"{self.color('comm:', 'BOLD', 'CYAN')} {user.comm.decode()} "
            f"{self.color('pid:', 'BOLD', 'CYAN')} {user.pid} "
            f"{self.color('tid:', 'BOLD', 'CYAN')} {user.tid} "
            f"{self.color('fd:', 'BOLD', 'CYAN')} {self.format_fd_info(user.fd)}"
        )

        if user.event_type == 0:
            print(f"{self.color('cmd:', 'BOLD', 'CYAN')} 0x{user.cmd:x} "
                  f"({self.color(name, 'YELLOW')})\n"
                  f"{self.color('arg:', 'BOLD', 'CYAN')} 0x{user.arg:x} "
                  f"[{self.decode_ioctl(user.cmd)}]")
        else:
            print(f"{self.color('arg:', 'BOLD', 'CYAN')} 0x{user.arg:x}")

        # Print user stack
        if user.user_stack_id >= 0:
            print(self.color("User stack:", 'BOLD', 'GREEN'))
            try:
                self.print_stack(
                    self.bpf["stack_traces"].walk(user.user_stack_id),
                    lambda addr: self.bpf.sym(addr, user.pid, show_offset=True
                                              ),
                    'GREEN',
                    'GRAY',
                    pid=user.pid)
            except KeyError:
                print(self.color("    [User stack unavailable]", 'GRAY'))
        else:
            print(self.color("    [User stack unavailable]", 'GRAY'))

        # Print kernel stack for all ioctl events
        if user.event_type in [0, 1]:
            print(self.color("Kernel stack:", 'BOLD', 'BLUE'))
            stack_source = kernel if user.event_type == 1 else user
            if stack_source.kernel_stack_id >= 0:
                try:
                    self.print_stack(
                        self.bpf["stack_traces"].walk(
                            stack_source.kernel_stack_id),
                        lambda addr: self.bpf.ksym(addr, show_offset=True),
                        'BLUE', 'GRAY')
                except KeyError:
                    print(self.color("    [Kernel stack unavailable]", 'GRAY'))
            else:
                print(self.color("    [Kernel stack unavailable]", 'GRAY'))

        print(self.color("=== END EVENT ===\n", 'BOLD', 'MAGENTA'))

    def handle_event(self, cpu, data, size):
        """Handle incoming BPF events."""
        if self.shutdown_requested:
            return

        try:
            event = ct.cast(data, ct.POINTER(Data)).contents
            comm = event.comm.decode().rstrip('\x00')
            if comm != self.target_comm:
                return

            key = (event.tid, event.arg)
            if event.event_type == 0:
                # ioctl: queue for kernel event
                self.user_events[key] = Data()
                ct.memmove(ct.addressof(self.user_events[key]),
                           ct.addressof(event), ct.sizeof(Data))
            elif event.event_type == 1:
                # amdgpu_drm_ioctl: pop and print
                user = self.user_events.pop(key, None)
                if user:
                    self.print_full_event(user, event)
            else:
                # sendmsg/recvmsg: print immediately
                self.print_full_event(event, None)
        except Exception:
            pass

    def run(self):
        """Start tracing."""
        print(
            self.color(
                f"Tracing ioctl/sendmsg/recvmsg for {self.target_comm}... Ctrl-C to end.",
                'BOLD'))
        time.sleep(2.0)

        def lost_cb(lost_count):
            if not self.shutdown_requested:
                print(f"ERROR: Lost {lost_count} events!")
                print("Ring buffer is overflowing. Try increasing page_cnt.")
                print("Even normal runs will likely overflow the buffer")
                self.shutdown_requested = True

        self.bpf["events"].open_perf_buffer(self.handle_event,
                                            page_cnt=1024,
                                            lost_cb=lost_cb)

        while not self.shutdown_requested:
            try:
                self.bpf.perf_buffer_poll(timeout=50)
            except:
                break

        print("Cleaning up...")


class Data(ct.Structure):
    """C structure for BPF event data."""
    _fields_ = [
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("fd", ct.c_ulonglong),
        ("cmd", ct.c_ulonglong),
        ("arg", ct.c_ulonglong),
        ("user_stack_id", ct.c_int),
        ("kernel_stack_id", ct.c_int),
        ("comm", ct.c_char * 16),
        ("event_type", ct.c_ubyte),
    ]


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: sudo ./trace_ioctl.py <binary> <cpp_file> <target_comm>")
        sys.exit(1)

    binary_path = sys.argv[1]
    cpp_file_path = sys.argv[2]
    target_comm = sys.argv[3]

    tracer = IOCTLTracer(binary_path, cpp_file_path, target_comm)
    tracer.run()

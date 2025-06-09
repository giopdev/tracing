#!/usr/bin/env python3

import re
import subprocess
import sys
import signal
import ctypes as ct
import os
import time
from bcc import BPF

AMDGPU_IOCTL_NAMES = {
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
}

I915_IOCTL_NAMES = {
    0xc0186448: "DRM_IOCTL_I915_ALLOC",
    0x40206443: "DRM_IOCTL_I915_BATCHBUFFER",
    0x4020644b: "DRM_IOCTL_I915_CMDBUFFER",
    0x4004644c: "DRM_IOCTL_I915_DESTROY_HEAP",
    0x6442: "DRM_IOCTL_I915_FLIP",
    0x6441: "DRM_IOCTL_I915_FLUSH",
    0x40086449: "DRM_IOCTL_I915_FREE",
    0xc0086457: "DRM_IOCTL_I915_GEM_BUSY",
    0xc008646d: "DRM_IOCTL_I915_GEM_CONTEXT_CREATE",
    0xc010646d: "DRM_IOCTL_I915_GEM_CONTEXT_CREATE_EXT",
    0x4008646e: "DRM_IOCTL_I915_GEM_CONTEXT_DESTROY",
    0xc0186474: "DRM_IOCTL_I915_GEM_CONTEXT_GETPARAM",
    0xc0186475: "DRM_IOCTL_I915_GEM_CONTEXT_SETPARAM",
    0xc010645b: "DRM_IOCTL_I915_GEM_CREATE",
    0xc018647c: "DRM_IOCTL_I915_GEM_CREATE_EXT",
    0x6459: "DRM_IOCTL_I915_GEM_ENTERVT",
    0x40286454: "DRM_IOCTL_I915_GEM_EXECBUFFER",
    0x40406469: "DRM_IOCTL_I915_GEM_EXECBUFFER2",
    0xc0406469: "DRM_IOCTL_I915_GEM_EXECBUFFER2_WR",
    0x80106463: "DRM_IOCTL_I915_GEM_GET_APERTURE",
    0xc0086470: "DRM_IOCTL_I915_GEM_GET_CACHING",
    0xc0106462: "DRM_IOCTL_I915_GEM_GET_TILING",
    0x40106453: "DRM_IOCTL_I915_GEM_INIT",
    0x645a: "DRM_IOCTL_I915_GEM_LEAVEVT",
    0xc00c6466: "DRM_IOCTL_I915_GEM_MADVISE",
    0xc028645e: "DRM_IOCTL_I915_GEM_MMAP",
    0xc0106464: "DRM_IOCTL_I915_GEM_MMAP_GTT",
    0xc0206464: "DRM_IOCTL_I915_GEM_MMAP_OFFSET",
    0xc0186455: "DRM_IOCTL_I915_GEM_PIN",
    0x4020645c: "DRM_IOCTL_I915_GEM_PREAD",
    0x4020645d: "DRM_IOCTL_I915_GEM_PWRITE",
    0x4008646f: "DRM_IOCTL_I915_GEM_SET_CACHING",
    0x400c645f: "DRM_IOCTL_I915_GEM_SET_DOMAIN",
    0xc0106461: "DRM_IOCTL_I915_GEM_SET_TILING",
    0x40046460: "DRM_IOCTL_I915_GEM_SW_FINISH",
    0x6458: "DRM_IOCTL_I915_GEM_THROTTLE",
    0x40086456: "DRM_IOCTL_I915_GEM_UNPIN",
    0xc0186473: "DRM_IOCTL_I915_GEM_USERPTR",
    0xc010647a: "DRM_IOCTL_I915_GEM_VM_CREATE",
    0x4010647b: "DRM_IOCTL_I915_GEM_VM_DESTROY",
    0xc010646c: "DRM_IOCTL_I915_GEM_WAIT",
    0xc0106446: "DRM_IOCTL_I915_GETPARAM",
    0xc0086465: "DRM_IOCTL_I915_GET_PIPE_FROM_CRTC_ID",
    0xc0186472: "DRM_IOCTL_I915_GET_RESET_STATS",
    0xc014646a: "DRM_IOCTL_I915_GET_SPRITE_COLORKEY",
    0x8004644e: "DRM_IOCTL_I915_GET_VBLANK_PIPE",
    0x40106451: "DRM_IOCTL_I915_HWS_ADDR",
    0x40446440: "DRM_IOCTL_I915_INIT",
    0x400c644a: "DRM_IOCTL_I915_INIT_HEAP",
    0xc0086444: "DRM_IOCTL_I915_IRQ_EMIT",
    0x40046445: "DRM_IOCTL_I915_IRQ_WAIT",
    0xc02c6468: "DRM_IOCTL_I915_OVERLAY_ATTRS",
    0x402c6467: "DRM_IOCTL_I915_OVERLAY_PUT_IMAGE",
    0x40486477: "DRM_IOCTL_I915_PERF_ADD_CONFIG",
    0x40106476: "DRM_IOCTL_I915_PERF_OPEN",
    0x40086478: "DRM_IOCTL_I915_PERF_REMOVE_CONFIG",
    0xc0106479: "DRM_IOCTL_I915_QUERY",
    0xc0106471: "DRM_IOCTL_I915_REG_READ",
    0x40086447: "DRM_IOCTL_I915_SETPARAM",
    0xc014646b: "DRM_IOCTL_I915_SET_SPRITE_COLORKEY",
    0x4004644d: "DRM_IOCTL_I915_SET_VBLANK_PIPE",
    0xc00c644f: "DRM_IOCTL_I915_VBLANK_SWAP",
}

SYNC_OBJ_IOCTL_NAMES = {
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


class IOCTLTracer:
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

    int trace_ppoll(struct tracepoint__syscalls__sys_enter_ppoll *args) {
        struct data_t data = {};
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 tid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.pid = pid;
        data.tid = tid;
        data.fd = (u64)args->ufds;
        data.cmd = args->nfds;
        data.arg = (u64)args->tsp;
        data.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
        data.kernel_stack_id = -1;
        data.event_type = 4;
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }
    """

    def __init__(self, binary_path, cpp_file_path, target_comm, ioctl_names):
        self.binary_path = binary_path
        self.cpp_file_path = cpp_file_path
        self.target_comm = target_comm
        self.IOCTL_NAMES = ioctl_names
        self.shutdown_requested = False
        self.fd_map = {}
        self.cpp_stack_pattern = re.compile(
            r'^(HelloTriangleApplication::[^\(]+)\(\)\+0x([0-9a-fA-F]+)$')

        self._map_file_descriptors()
        self.bpf = BPF(text=self.BPF_PROGRAM)
        self._setup_tracing()
        self._setup_signal_handler()

    def _find_pids_by_name(self, proc_name):
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
        self.bpf.attach_tracepoint(tp="syscalls:sys_enter_ioctl",
                                   fn_name="trace_ioctl")
        self.bpf.attach_tracepoint(tp="syscalls:sys_enter_recvmsg",
                                   fn_name="trace_recvmsg")
        self.bpf.attach_tracepoint(tp="syscalls:sys_enter_sendmsg",
                                   fn_name="trace_sendmsg")
        self.bpf.attach_tracepoint(tp="syscalls:sys_enter_ppoll",
                                   fn_name="trace_ppoll")

    def _setup_signal_handler(self):
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        print("\nShutdown requested...")
        self.shutdown_requested = True

    def color(self, text, *colors):
        color_codes = ''.join(self.COLORS[c] for c in colors)
        return f"{color_codes}{text}{self.COLORS['RESET']}"

    # https://elixir.bootlin.com/linux/v6.15.1/source/include/uapi/asm-generic/ioctl.h
    # https://docs.kernel.org/userspace-api/ioctl/ioctl-decoding.html
    @staticmethod
    def decode_ioctl(cmd):
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
        result = subprocess.run(["nm", "-C", self.binary_path],
                                stdout=subprocess.PIPE,
                                text=True)
        for line in result.stdout.splitlines():
            if function in line:
                addr = line.split()[0]
                return int(addr, 16)
        return None

    def addr2line(self, address):
        result = subprocess.run(
            ["addr2line", "-e", self.binary_path,
             hex(address)],
            stdout=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()

    def get_source_line(self, line_number):
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
        unknown_count = 0

        for addr in frames:
            sym = resolve_fn(addr)
            if isinstance(sym, bytes):
                sym = sym.decode(errors="replace")

            is_unknown = sym == "[unknown]" or sym == "b'[unknown]'"

            if is_unknown:
                unknown_count += 1
                continue

            if unknown_count > 0:
                print(
                    f"    {self.color(
                        f'unknown (x{unknown_count})', color_unknown)}"
                )
                unknown_count = 0

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
                                    f"    {self.color(
                                        f'<src:{line_num-1}>', 'YELLOW')}\t"
                                    f"{self.color(code_line_prev, 'YELLOW')}")
                                print(
                                    f"        {self.color(
                                        f'--->{line_num_str}>', 'YELLOW')}\t"
                                    f"{self.color(code_line, 'YELLOW')}")
                            elif "vkAcquireNextImageKHR" in code_line_prev:
                                print(
                                    f"    {self.color(
                                        f'<src:{line_num-1}>', 'YELLOW')}\t"
                                    f"{self.color(code_line_prev, 'YELLOW')}")
                                print(
                                    f"        {self.color(
                                        f'--->{line_num_str}>', 'YELLOW')}\t"
                                    f"{self.color(code_line, 'YELLOW')}")
                            else:
                                print(
                                    f"    {self.color(
                                        f'<src:{line_num_str}>', color_stack)}\t"
                                    f"{self.color(code_line, color_stack)}")
                            continue

            print(f"    {self.color(sym, color_stack)}")

        if unknown_count > 0:
            print(
                f"    {self.color(
                    f'unknown (x{unknown_count})', color_unknown)}"
            )

    def format_fd_info(self, fd):
        fd_target = self.fd_map.get(fd, "unknown")
        return f"{fd} ({self.color(fd_target, 'YELLOW')})"

    def _format_ppoll_fds(self, ufds_ptr, nfds, pid):
        """Format the pollfd array for ppoll display"""
        if nfds == 0 or nfds > 64:  # Sanity check
            return f"[invalid nfds={nfds}]"

        try:
            import struct

            mem_file = f"/proc/{pid}/mem"
            try:
                with open(mem_file, 'rb') as f:
                    f.seek(ufds_ptr)
                    data = f.read(8 * nfds)

                    fds = []
                    for i in range(nfds):
                        offset = i * 8
                        fd, events, revents = struct.unpack(
                            'ihh', data[offset:offset+8])
                        fd_target = self.fd_map.get(fd, "unknown")
                        events_str = self._format_poll_events(events)
                        fds.append(
                            f"{{fd={fd}({self.color(fd_target, 'YELLOW')}), events={events_str}}}")

                    return f"[{', '.join(fds)}]"
            except:
                pass

        except Exception:
            pass

        # Fallback: just show the pointer and count
        return f"[ufds=0x{ufds_ptr:x}, nfds={nfds}]"

    def _format_poll_events(self, events):
        """Format poll events bitmask"""
        event_names = []
        if events & 0x001:
            event_names.append("POLLIN")
        if events & 0x002:
            event_names.append("POLLPRI")
        if events & 0x004:
            event_names.append("POLLOUT")
        if events & 0x008:
            event_names.append("POLLERR")
        if events & 0x010:
            event_names.append("POLLHUP")
        if events & 0x020:
            event_names.append("POLLNVAL")

        if event_names:
            return "|".join(event_names)
        else:
            return f"0x{events:x}"

    def print_full_event(self, user, kernel):
        syscall_name = {
            0: "ioctl",
            2: "recvmsg",
            3: "sendmsg",
            4: "ppoll"
        }.get(user.event_type, "unknown")

        name = self.IOCTL_NAMES.get(user.cmd,
                                    "UNKNOWN") if user.event_type == 0 else ""

        print(
            self.color(f"=== {syscall_name.upper()} EVENT ===", 'BOLD',
                       'MAGENTA'))

        if user.event_type == 4:  # ppoll - special handling
            fds_info = self._format_ppoll_fds(user.fd, user.cmd, user.pid)
            print(
                f"{self.color('comm:', 'BOLD', 'CYAN')} {user.comm.decode()} "
                f"{self.color('pid:', 'BOLD', 'CYAN')} {user.pid} "
                f"{self.color('tid:', 'BOLD', 'CYAN')} {user.tid}"
            )
            print(f"{self.color('fds:', 'BOLD', 'CYAN')} {fds_info}")
            print(f"{self.color('nfds:', 'BOLD', 'CYAN')} {user.cmd} "
                  f"{self.color('timeout:', 'BOLD', 'CYAN')} 0x{user.arg:x}")
        else:
            print(
                f"{self.color('comm:', 'BOLD', 'CYAN')} {user.comm.decode()} "
                f"{self.color('pid:', 'BOLD', 'CYAN')} {user.pid} "
                f"{self.color('tid:', 'BOLD', 'CYAN')} {user.tid} "
                f"{self.color('fd:', 'BOLD', 'CYAN')} {
                    self.format_fd_info(user.fd)}"
            )

            if user.event_type == 0:
                print(f"{self.color('cmd:', 'BOLD', 'CYAN')} 0x{user.cmd:x} "
                      f"({self.color(name, 'YELLOW')})\n"
                      f"{self.color('arg:', 'BOLD', 'CYAN')} 0x{user.arg:x} "
                      f"[{self.decode_ioctl(user.cmd)}]")
            else:
                print(f"{self.color('arg:', 'BOLD', 'CYAN')} 0x{user.arg:x}")

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

        print(self.color("=== END EVENT ===\n", 'BOLD', 'MAGENTA'))

    def handle_event(self, cpu, data, size):
        if self.shutdown_requested:
            return

        try:
            event = ct.cast(data, ct.POINTER(Data)).contents
            comm = event.comm.decode().rstrip('\x00')
            if comm != self.target_comm:
                return

            self.print_full_event(event, None)
        except Exception:
            pass

    def run(self):
        print(
            self.color(
                f"Tracing ioctl/sendmsg/recvmsg/ppoll for {
                    self.target_comm}... Ctrl-C to end.",
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
    if len(sys.argv) != 5:
        print(
            "Usage: sudo ./triangleTrace.py <binary> <cpp_file> <target_comm> <amd|intel>")
        sys.exit(1)

    binary_path = sys.argv[1]
    cpp_file_path = sys.argv[2]
    target_comm = sys.argv[3]
    gpu = sys.argv[4].lower()

    if gpu == "amd":
        ioctl_names = {**AMDGPU_IOCTL_NAMES, **SYNC_OBJ_IOCTL_NAMES}
    elif gpu == "intel":
        ioctl_names = {**I915_IOCTL_NAMES, **SYNC_OBJ_IOCTL_NAMES}
    else:
        print("Unknown GPU type. Use 'amd' or 'intel'.")
        sys.exit(1)

    tracer = IOCTLTracer(binary_path, cpp_file_path, target_comm, ioctl_names)
    tracer.run()

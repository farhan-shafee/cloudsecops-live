"""Contain only the trusted worker tree created by the offline runner.

Linux workers retain their new session/process group and must not daemonize or
change groups. Windows jobs prohibit ordinary CreateProcess breakaway. These
mechanisms are lifecycle controls, not a hostile native-code sandbox.
"""

from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import sys
import time
from ctypes import wintypes
from typing import Any, cast


class ContainmentError(RuntimeError):
    """A fixed internal error, with no OS exception text."""


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimits),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _Accounting(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),
        ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class ProcessTree:
    """The direct child remains unreaped until the final group signal is sent."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self._job: Any = None
        self._kernel: Any = None
        if sys.platform == "win32":
            self._windows_job()
        elif sys.platform == "linux":
            if os.getpgid(process.pid) != process.pid:
                raise ContainmentError("AWS_RUNNER_CONTAINMENT")
        else:
            raise ContainmentError("AWS_RUNNER_PLATFORM")

    def _windows_job(self) -> None:
        kernel = cast(Any, ctypes).WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.IsProcessInJob.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.BOOL),
        ]
        kernel.IsProcessInJob.restype = wintypes.BOOL
        kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateJobObject.restype = wintypes.BOOL
        kernel.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        kernel.QueryInformationJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        job = kernel.CreateJobObjectW(None, None)
        if not job:
            raise ContainmentError("AWS_RUNNER_CONTAINMENT")
        self._job, self._kernel = job, kernel
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE; no breakaway.
        handle = int(cast(Any, self.process)._handle)
        assigned = wintypes.BOOL()
        if not (
            kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits))
            and kernel.AssignProcessToJobObject(job, handle)
            and kernel.IsProcessInJob(handle, job, ctypes.byref(assigned))
            and assigned.value
        ):
            self.close()
            raise ContainmentError("AWS_RUNNER_CONTAINMENT")

    def terminate(self, deadline: float) -> bool:
        """Signal the owned tree once, then verify termination within the budget."""
        if sys.platform == "win32":
            if not self._kernel.TerminateJobObject(self._job, 125):
                return False
        else:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                return False
        try:
            self.process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except (subprocess.TimeoutExpired, OSError):
            return False
        while time.monotonic() < deadline:
            if sys.platform == "win32":
                accounting = _Accounting()
                if not self._kernel.QueryInformationJobObject(
                    self._job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None
                ):
                    return False
                if accounting.ActiveProcesses == 0:
                    return True
            else:
                # Query only after reaping: never send another signal to a possibly
                # reused PGID. Zombies have terminated, even before init reaps them.
                if not self._linux_live_members(deadline):
                    return True
            time.sleep(min(0.005, max(0.0, deadline - time.monotonic())))
        return False

    def _linux_live_members(self, deadline: float) -> bool:
        try:
            cast(Any, os).killpg(self.process.pid, 0)  # Query only; never another kill.
        except ProcessLookupError:
            return False
        except OSError:
            return True
        observed_member = False
        try:
            for name in os.listdir("/proc"):
                if time.monotonic() >= deadline:
                    return True
                if not name.isdecimal():
                    continue
                try:
                    if cast(Any, os).getpgid(int(name)) != self.process.pid:
                        continue
                except ProcessLookupError:
                    continue
                except OSError:
                    return True
                try:
                    with open(f"/proc/{name}/stat", encoding="ascii") as source:
                        fields = source.read(8192).rsplit(")", 1)[1].split()
                    if int(fields[2]) != self.process.pid:
                        return True
                    observed_member = True
                    if fields[0] not in ("Z", "X"):
                        return True
                except (FileNotFoundError, ProcessLookupError):
                    continue
                except (OSError, ValueError, IndexError):
                    return True
        except OSError:
            return True
        # An existing group with no readable members is not proof of cleanup.
        return not observed_member

    def close(self) -> None:
        if self._job is not None:
            self._kernel.CloseHandle(self._job)
            self._job = None

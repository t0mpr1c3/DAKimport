#!/usr/bin/env python3
"""Dump the in-memory images of a running (unpacked) Windows process.

DesignaKnit's dk9.exe and dk9a.dll are Themida-protected: their code exists
in readable form only after the program has started. This script either
launches the program or attaches to a running process. It then copies the
mapped image of each requested module with ReadProcessMemory into
``<outdir>/<module>.mem`` and records the base addresses in
``<outdir>/modules.json``. Use ``tools/mem_to_pe.py`` to turn a ``.mem``
file into a PE that Ghidra can load.

    python tools/dump_process_modules.py --launch "C:\\...\\dk9.exe" \\
        --wait 25 --out dumps dk9.exe dk9a.dll

Windows only, standard library only (ctypes). A 64-bit Python can dump a
32-bit (WOW64) process.
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
import time

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("PartitionId", wt.WORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD),
                ("Protect", wt.DWORD),
                ("Type", wt.DWORD)]


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                ("SizeOfImage", wt.DWORD),
                ("EntryPoint", ctypes.c_void_p)]


k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p,
                               ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                               ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
psapi.EnumProcessModulesEx.argtypes = [wt.HANDLE, ctypes.POINTER(wt.HMODULE),
                                       wt.DWORD, ctypes.POINTER(wt.DWORD),
                                       wt.DWORD]
psapi.GetModuleBaseNameW.argtypes = [wt.HANDLE, wt.HMODULE, wt.LPWSTR,
                                     wt.DWORD]
psapi.GetModuleInformation.argtypes = [wt.HANDLE, wt.HMODULE,
                                       ctypes.POINTER(MODULEINFO), wt.DWORD]


def find_pid(image_name):
    out = subprocess.run(["tasklist", "/FO", "CSV", "/NH", "/FI",
                          "IMAGENAME eq " + image_name],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if parts and parts[0].lower() == image_name.lower():
            return int(parts[1])
    return None


def modules(handle):
    arr = (wt.HMODULE * 1024)()
    needed = wt.DWORD()
    if not psapi.EnumProcessModulesEx(handle, arr, ctypes.sizeof(arr),
                                      ctypes.byref(needed), LIST_MODULES_ALL):
        raise OSError(ctypes.get_last_error(), "EnumProcessModulesEx failed")
    result = {}
    for i in range(needed.value // ctypes.sizeof(wt.HMODULE)):
        name = ctypes.create_unicode_buffer(260)
        psapi.GetModuleBaseNameW(handle, arr[i], name, 260)
        info = MODULEINFO()
        psapi.GetModuleInformation(handle, arr[i], ctypes.byref(info),
                                   ctypes.sizeof(info))
        result[name.value.lower()] = (info.lpBaseOfDll, info.SizeOfImage,
                                      info.EntryPoint)
    return result


def read_image(handle, base, size):
    """Read [base, base+size) page region by page region; unreadable
    regions are left as zero bytes. Returns (bytes, list of regions)."""
    out = bytearray(size)
    regions = []
    addr = base
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < base + size:
        if not k32.VirtualQueryEx(handle, addr, ctypes.byref(mbi),
                                  ctypes.sizeof(mbi)):
            break
        start = mbi.BaseAddress
        end = min(start + mbi.RegionSize, base + size)
        readable = (mbi.State == MEM_COMMIT and not mbi.Protect & PAGE_GUARD
                    and mbi.Protect != PAGE_NOACCESS)
        if readable:
            buf = ctypes.create_string_buffer(end - start)
            got = ctypes.c_size_t()
            ok = k32.ReadProcessMemory(handle, start, buf, end - start,
                                       ctypes.byref(got))
            if ok:
                out[start - base:end - base] = buf.raw[:got.value]
        regions.append({"start": hex(start), "size": hex(end - start),
                        "protect": hex(mbi.Protect), "state": hex(mbi.State),
                        "read": bool(readable)})
        addr = end
    return bytes(out), regions


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--launch", help="program to start (its folder is used "
                    "as the working directory)")
    ap.add_argument("--args", nargs="*", default=[],
                    help="arguments for the launched program")
    ap.add_argument("--pid", type=int)
    ap.add_argument("--wait", type=float, default=20,
                    help="seconds to wait after launching")
    ap.add_argument("--out", required=True)
    ap.add_argument("modules", nargs="+", help="module names to dump")
    a = ap.parse_args(argv)

    pid = a.pid
    if a.launch:
        proc = subprocess.Popen([a.launch] + a.args,
                                cwd=os.path.dirname(a.launch))
        pid = proc.pid
        print("launched pid", pid, "- waiting", a.wait, "s")
        time.sleep(a.wait)
    if pid is None:
        pid = find_pid(a.modules[0])
    if pid is None:
        sys.exit("process not found")

    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                             False, pid)
    if not handle:
        sys.exit("OpenProcess failed: {}".format(ctypes.get_last_error()))
    mods = modules(handle)
    os.makedirs(a.out, exist_ok=True)
    meta = {"pid": pid, "modules": {}}
    for name in a.modules:
        if name.lower() not in mods:
            print("module not loaded:", name)
            continue
        base, size, entry = mods[name.lower()]
        image, regions = read_image(handle, base, size)
        path = os.path.join(a.out, name + ".mem")
        with open(path, "wb") as f:
            f.write(image)
        meta["modules"][name] = {"base": hex(base), "size": hex(size),
                                 "entry": hex(entry or 0),
                                 "regions": regions}
        print("dumped {} base={:#x} size={:#x} -> {}".format(
            name, base, size, path))
    meta["all_modules"] = dict((k, hex(v[0])) for k, v in mods.items())
    with open(os.path.join(a.out, "modules.json"), "w") as f:
        json.dump(meta, f, indent=1)
    k32.CloseHandle(handle)


if __name__ == "__main__":
    main()

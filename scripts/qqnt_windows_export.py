#!/usr/bin/env python3
"""Windows QQ NT 数据库导出辅助脚本。

脚本不依赖固定版本偏移，而是静态解析 ``wrapper.node``：

1. 在只读数据段中定位 ``nt_sqlite3_key_v2: db=%p zDb=%s``。
2. 在代码段中查找引用该字符串的 RIP-relative LEA 指令。
3. 通过 PE exception directory 找到包含该引用的函数入口。
4. 默认使用 Windows Debug API 在 QQ 启动早期下断点，从 x64 第三参数 R8 读取数据库 key。
5. 获取 key 后复制 ``nt_msg.db`` 及 WAL/SHM/material sidecar 到输出目录。

脚本默认优先使用 ``rotki-pysqlcipher3`` 导出明文库；如果当前 Python
环境没有可用的 pysqlcipher3，则回退到 SQLCipher CLI。若 CLI 不在 PATH，
请通过 ``--sqlcipher`` 传入真实可执行文件路径。
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import struct
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from ctypes import wintypes

try:
    import winreg
except ImportError:  # pragma: no cover - 该脚本只面向 Windows。
    winreg = None


TARGET_LOG_STRING = b"nt_sqlite3_key_v2: db=%p zDb=%s"
DEFAULT_DB_BASENAME = "nt_msg.db"


class ScriptError(RuntimeError):
    """可预期的用户侧错误。"""


if os.name == "nt":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
else:  # pragma: no cover - Windows-only backend.
    kernel32 = None


DWORD = wintypes.DWORD
WORD = wintypes.WORD
BYTE = ctypes.c_ubyte
BOOL = wintypes.BOOL
HANDLE = wintypes.HANDLE
LPVOID = wintypes.LPVOID
LPCVOID = wintypes.LPCVOID
ULONG64 = ctypes.c_ulonglong
LONG64 = ctypes.c_longlong
SIZE_T = ctypes.c_size_t

DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_NEW_PROCESS_GROUP = 0x00000200
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 1
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
THREAD_ALL_ACCESS = 0x001F03FF
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002
CONTEXT_CONTROL_INTEGER = CONTEXT_CONTROL | CONTEXT_INTEGER


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPVOID),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("_padding", DWORD),
        ("u", BYTE * 160),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("th32ModuleID", DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage", DWORD),
        ("ProccntUsage", DWORD),
        ("modBaseAddr", LPVOID),
        ("modBaseSize", DWORD),
        ("hModule", HANDLE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    ]


class M128A(ctypes.Structure):
    _fields_ = [("Low", ULONG64), ("High", LONG64)]


class XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", BYTE * 96),
    ]


class CONTEXT64(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
        ("P1Home", ULONG64),
        ("P2Home", ULONG64),
        ("P3Home", ULONG64),
        ("P4Home", ULONG64),
        ("P5Home", ULONG64),
        ("P6Home", ULONG64),
        ("ContextFlags", DWORD),
        ("MxCsr", DWORD),
        ("SegCs", WORD),
        ("SegDs", WORD),
        ("SegEs", WORD),
        ("SegFs", WORD),
        ("SegGs", WORD),
        ("SegSs", WORD),
        ("EFlags", DWORD),
        ("Dr0", ULONG64),
        ("Dr1", ULONG64),
        ("Dr2", ULONG64),
        ("Dr3", ULONG64),
        ("Dr6", ULONG64),
        ("Dr7", ULONG64),
        ("Rax", ULONG64),
        ("Rcx", ULONG64),
        ("Rdx", ULONG64),
        ("Rbx", ULONG64),
        ("Rsp", ULONG64),
        ("Rbp", ULONG64),
        ("Rsi", ULONG64),
        ("Rdi", ULONG64),
        ("R8", ULONG64),
        ("R9", ULONG64),
        ("R10", ULONG64),
        ("R11", ULONG64),
        ("R12", ULONG64),
        ("R13", ULONG64),
        ("R14", ULONG64),
        ("R15", ULONG64),
        ("Rip", ULONG64),
        ("FltSave", XMM_SAVE_AREA32),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ULONG64),
        ("DebugControl", ULONG64),
        ("LastBranchToRip", ULONG64),
        ("LastBranchFromRip", ULONG64),
        ("LastExceptionToRip", ULONG64),
        ("LastExceptionFromRip", ULONG64),
    ]


def configure_winapi() -> None:
    if kernel32 is None:
        return
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        LPVOID,
        LPVOID,
        BOOL,
        DWORD,
        LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    kernel32.CreateProcessW.restype = BOOL
    kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), DWORD]
    kernel32.WaitForDebugEvent.restype = BOOL
    kernel32.ContinueDebugEvent.argtypes = [DWORD, DWORD, DWORD]
    kernel32.ContinueDebugEvent.restype = BOOL
    kernel32.ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]
    kernel32.ReadProcessMemory.restype = BOOL
    kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, SIZE_T, ctypes.POINTER(SIZE_T)]
    kernel32.WriteProcessMemory.restype = BOOL
    kernel32.FlushInstructionCache.argtypes = [HANDLE, LPCVOID, SIZE_T]
    kernel32.FlushInstructionCache.restype = BOOL
    kernel32.OpenThread.argtypes = [DWORD, BOOL, DWORD]
    kernel32.OpenThread.restype = HANDLE
    kernel32.GetThreadContext.argtypes = [HANDLE, ctypes.POINTER(CONTEXT64)]
    kernel32.GetThreadContext.restype = BOOL
    kernel32.SetThreadContext.argtypes = [HANDLE, ctypes.POINTER(CONTEXT64)]
    kernel32.SetThreadContext.restype = BOOL
    kernel32.CloseHandle.argtypes = [HANDLE]
    kernel32.CloseHandle.restype = BOOL
    kernel32.TerminateProcess.argtypes = [HANDLE, DWORD]
    kernel32.TerminateProcess.restype = BOOL
    kernel32.CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = HANDLE
    kernel32.Module32FirstW.argtypes = [HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32FirstW.restype = BOOL
    kernel32.Module32NextW.argtypes = [HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32NextW.restype = BOOL


configure_winapi()


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_pointer: int
    raw_size: int

    @property
    def raw_end(self) -> int:
        return self.raw_pointer + self.raw_size

    @property
    def virtual_end(self) -> int:
        return self.virtual_address + max(self.virtual_size, self.raw_size)


@dataclass(frozen=True)
class KeyFunctionCandidate:
    string_rva: int
    lea_rva: int
    function_rva: int


@dataclass
class QQInstall:
    install_dir: Path
    qq_exe: Path
    version: str | None
    wrapper_node: Path


@dataclass
class HookResult:
    key: str
    raw_hex: str
    n_key: int
    z_db: str
    pid: int
    base: str | None = None
    target: str | None = None


class PEImage:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        self.sections: list[Section] = []
        self.image_base = 0
        self.exception_rva = 0
        self.exception_size = 0
        self._parse()

    def _parse(self) -> None:
        if len(self.data) < 0x100 or self._u16(0) != 0x5A4D:
            raise ScriptError(f"不是有效 PE 文件: {self.path}")

        pe_offset = self._u32(0x3C)
        if self._u32(pe_offset) != 0x00004550:
            raise ScriptError("PE 签名无效")

        coff = pe_offset + 4
        machine = self._u16(coff)
        if machine != 0x8664:
            raise ScriptError(f"仅支持 x86-64 PE 文件，当前 machine=0x{machine:X}")

        number_of_sections = self._u16(coff + 2)
        optional_size = self._u16(coff + 16)
        optional = coff + 20
        magic = self._u16(optional)
        if magic != 0x20B:
            raise ScriptError(f"仅支持 PE32+ 文件，当前 magic=0x{magic:X}")

        self.image_base = self._u64(optional + 24)
        data_dirs = optional + 112
        self.exception_rva = self._u32(data_dirs + 3 * 8)
        self.exception_size = self._u32(data_dirs + 3 * 8 + 4)

        section_table = optional + optional_size
        for index in range(number_of_sections):
            off = section_table + index * 40
            name = self.data[off : off + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
            self.sections.append(
                Section(
                    name=name,
                    virtual_size=self._u32(off + 8),
                    virtual_address=self._u32(off + 12),
                    raw_size=self._u32(off + 16),
                    raw_pointer=self._u32(off + 20),
                )
            )

    def _u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, offset)[0]

    def _u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]

    def _u64(self, offset: int) -> int:
        return struct.unpack_from("<Q", self.data, offset)[0]

    def section(self, name: str) -> Section | None:
        return next((section for section in self.sections if section.name == name), None)

    def section_containing_rva(self, rva: int) -> Section | None:
        for section in self.sections:
            if section.virtual_address <= rva < section.virtual_end:
                return section
        return None

    def rva_to_offset(self, rva: int) -> int:
        section = self.section_containing_rva(rva)
        if section is None:
            raise ScriptError(f"RVA 0x{rva:X} 不属于任何节")
        return section.raw_pointer + (rva - section.virtual_address)

    def file_offset_to_rva(self, offset: int) -> int:
        for section in self.sections:
            if section.raw_pointer <= offset < section.raw_end:
                return section.virtual_address + (offset - section.raw_pointer)
        raise ScriptError(f"文件偏移 0x{offset:X} 不属于任何节")


def find_all(data: bytes, needle: bytes, start: int = 0, end: int | None = None) -> Iterable[int]:
    if end is None:
        end = len(data)
    pos = start
    while pos < end:
        hit = data.find(needle, pos, end)
        if hit < 0:
            return
        yield hit
        pos = hit + 1


def find_key_function(wrapper_node: Path) -> KeyFunctionCandidate:
    image = PEImage(wrapper_node)
    rdata = image.section(".rdata")
    text = image.section(".text")
    if text is None:
        raise ScriptError("未找到 .text 节")

    search_ranges: list[tuple[int, int]]
    if rdata is not None:
        search_ranges = [(rdata.raw_pointer, rdata.raw_end)]
    else:
        search_ranges = [(0, len(image.data))]

    string_rvas: list[int] = []
    for start, end in search_ranges:
        for file_offset in find_all(image.data, TARGET_LOG_STRING, start, end):
            string_rvas.append(image.file_offset_to_rva(file_offset))

    if not string_rvas and rdata is not None:
        for file_offset in find_all(image.data, TARGET_LOG_STRING):
            string_rvas.append(image.file_offset_to_rva(file_offset))

    if not string_rvas:
        raise ScriptError("未找到目标字符串: nt_sqlite3_key_v2: db=%p zDb=%s")

    text_bytes = image.data[text.raw_pointer : text.raw_end]
    candidates: list[KeyFunctionCandidate] = []
    for string_rva in string_rvas:
        for lea_rva in find_rip_relative_lea_refs(text_bytes, text.virtual_address, string_rva):
            function_rva = find_runtime_function_start(image, lea_rva)
            if function_rva is not None:
                candidates.append(KeyFunctionCandidate(string_rva, lea_rva, function_rva))

    if not candidates:
        raise ScriptError("未找到引用目标字符串的函数")

    return candidates[0]


def find_rip_relative_lea_refs(text_bytes: bytes, text_rva: int, target_rva: int) -> Iterable[int]:
    # Match REX + LEA r64, [rip+disp32]. The PowerShell implementation from
    # QQBackup uses the same operand-shape test: current byte 0x8D, previous
    # byte REX, and ModRM rm=101 mod=00.
    for i in range(1, len(text_bytes) - 6):
        if text_bytes[i] != 0x8D:
            continue
        rex = text_bytes[i - 1]
        if rex & 0xF8 != 0x48:
            continue
        modrm = text_bytes[i + 1]
        if modrm & 0xC7 != 0x05:
            continue
        disp = struct.unpack_from("<i", text_bytes, i + 2)[0]
        instr_rva = text_rva + i - 1
        if instr_rva + 7 + disp == target_rva:
            yield instr_rva


def find_runtime_function_start(image: PEImage, rva: int) -> int | None:
    if not image.exception_rva or not image.exception_size:
        return None
    try:
        exception_offset = image.rva_to_offset(image.exception_rva)
    except ScriptError:
        return None

    entry_count = image.exception_size // 12
    left, right = 0, entry_count - 1
    while left <= right:
        mid = (left + right) // 2
        off = exception_offset + mid * 12
        begin, end, _unwind = struct.unpack_from("<III", image.data, off)
        if rva < begin:
            right = mid - 1
        elif rva >= end:
            left = mid + 1
        else:
            return begin
    return None


def normalize_qq_version(version: str | None) -> str | None:
    if not version:
        return None
    version = version.strip()
    if "-" in version:
        return version
    parts = version.split(".")
    if len(parts) >= 4:
        return ".".join(parts[:3]) + "-" + parts[3]
    return version


def query_reg_string(root, subkey: str, value: str, access: int = 0) -> str | None:
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | access) as key:
            data, _kind = winreg.QueryValueEx(key, value)
            return str(data)
    except OSError:
        return None


def strip_exe_path(command: str) -> Path | None:
    command = command.strip()
    if not command:
        return None
    if command.startswith('"'):
        end = command.find('"', 1)
        if end > 1:
            return Path(command[1:end])
    marker = ".exe"
    index = command.lower().find(marker)
    if index >= 0:
        return Path(command[: index + len(marker)])
    return Path(command.split(" ", 1)[0])


def detect_qq_install(qq_exe_arg: str | None = None, wrapper_arg: str | None = None) -> QQInstall:
    version = query_reg_string(winreg.HKEY_CURRENT_USER, r"Software\Tencent\QQNT", "version") if winreg else None
    normalized_version = normalize_qq_version(version)

    qq_exe = Path(qq_exe_arg).expanduser() if qq_exe_arg else None
    install_dir: Path | None = qq_exe.parent if qq_exe else None

    if install_dir is None and winreg is not None:
        uninstall_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\QQ", 0),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NTQQ", 0),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\QQ", 0),
        ]
        for root, subkey, access in uninstall_keys:
            uninstall = query_reg_string(root, subkey, "UninstallString", access)
            icon = query_reg_string(root, subkey, "DisplayIcon", access)
            path = strip_exe_path(icon or "") or strip_exe_path(uninstall or "")
            if path:
                candidate_dir = path.parent
                candidate_qq = candidate_dir / "QQ.exe"
                if candidate_qq.exists():
                    install_dir = candidate_dir
                    qq_exe = candidate_qq
                    break

    if install_dir is None or qq_exe is None:
        for candidate in [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Tencent" / "QQNT" / "QQ.exe",
            Path("C:/Program Files/Tencent/QQNT/QQ.exe"),
            Path("C:/Program Files (x86)/Tencent/QQNT/QQ.exe"),
            Path("D:/Program Files/Tencent/QQNT/QQ.exe"),
        ]:
            if candidate.exists():
                qq_exe = candidate
                install_dir = candidate.parent
                break

    if install_dir is None or qq_exe is None or not qq_exe.exists():
        raise ScriptError("未找到 QQ.exe，请用 --qq-exe 手动指定。")

    wrapper_node = Path(wrapper_arg).expanduser() if wrapper_arg else None
    if wrapper_node is None:
        versions_dir = install_dir / "versions"
        version_dir = versions_dir / normalized_version if normalized_version else None
        if version_dir is None or not version_dir.exists():
            candidates = sorted(
                [path for path in versions_dir.glob("*") if path.is_dir()],
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            if not candidates:
                raise ScriptError(f"未找到 QQ 版本目录: {versions_dir}")
            version_dir = candidates[0]
            normalized_version = version_dir.name
        wrapper_node = version_dir / "resources" / "app" / "wrapper.node"

    if not wrapper_node.exists():
        raise ScriptError(f"未找到 wrapper.node: {wrapper_node}")

    return QQInstall(
        install_dir=install_dir,
        qq_exe=qq_exe,
        version=normalized_version or version,
        wrapper_node=wrapper_node,
    )


def find_default_db_dir(account: str | None = None, db_basename: str = DEFAULT_DB_BASENAME) -> Path | None:
    base = Path.home() / "Documents" / "Tencent Files"
    if account:
        db_dir = base / account / "nt_qq" / "nt_db"
        return db_dir if (db_dir / db_basename).exists() else None

    candidates = sorted(base.glob(f"*/nt_qq/nt_db/{db_basename}"), key=lambda path: path.stat().st_mtime, reverse=True)
    if len(candidates) == 1:
        return candidates[0].parent
    if len(candidates) > 1:
        accounts = ", ".join(path.parts[-4] for path in candidates[:10])
        raise ScriptError(f"发现多个 QQ 数据库目录 ({accounts})，请用 --account 指定账号。")
    return None


def copy_db_bundle(db_dir: Path, outdir: Path, db_basename: str = DEFAULT_DB_BASENAME) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    names = [
        db_basename,
        f"{db_basename}-wal",
        f"{db_basename}-shm",
        f"{db_basename}-first.material",
        f"{db_basename}-last.material",
    ]
    for name in names:
        source = db_dir / name
        if source.exists():
            destination = outdir / name
            shutil.copy2(source, destination)
            copied.append(destination)
    return copied


def find_qq_processes(device) -> list:
    return [proc for proc in device.enumerate_processes() if proc.name.lower() == "qq.exe" or proc.name.lower() == "qq"]


def make_frida_script(function_rva: int, module_name: str = "wrapper.node") -> str:
    return f"""
'use strict';

const moduleName = {json.dumps(module_name)};
const functionRva = ptr('{function_rva:#x}');
let installed = false;

function installHookForBase(base) {{
  if (installed) return;
  if (base === null) {{
    return;
  }}

  const target = base.add(functionRva);
  Interceptor.attach(target, {{
    onEnter(args) {{
      let zDb = '';
      let nKey = -1;
      try {{ zDb = isNullPtr(args[1]) ? '' : Memory.readUtf8String(args[1]); }} catch (_) {{}}
      try {{ nKey = args[3].toInt32(); }} catch (_) {{}}

      if (isNullPtr(args[2]) || nKey <= 0 || nKey > 512) {{
        send({{ type: 'candidate', zDb: zDb, nKey: nKey, pKey: args[2].toString() }});
        return;
      }}

      try {{
        const bytes = Memory.readByteArray(args[2], nKey);
        let keyText = '';
        try {{ keyText = Memory.readAnsiString(args[2], nKey); }} catch (_) {{}}
        send({{
          type: 'key',
          db: args[0].toString(),
          zDb: zDb,
          pKey: args[2].toString(),
          nKey: nKey,
          keyText: keyText,
          base: base.toString(),
          target: target.toString()
        }}, bytes);
      }} catch (e) {{
        send({{ type: 'read-error', message: e.message, zDb: zDb, nKey: nKey }});
      }}
    }}
  }});

  installed = true;
  send({{ type: 'hook-installed', module: moduleName, base: base.toString(), target: target.toString() }});
}}

function installHook() {{
  installHookForBase(findModuleBase(moduleName));
  if (!installed) setTimeout(installHook, 25);
}}

function findModuleBase(name) {{
  if (typeof Module !== 'undefined' && typeof Module.findBaseAddress === 'function') {{
    return Module.findBaseAddress(name);
  }}
  const lower = name.toLowerCase();
  const modules = Process.enumerateModules();
  for (let i = 0; i < modules.length; i++) {{
    const moduleName = modules[i].name.toLowerCase();
    const modulePath = modules[i].path.toLowerCase();
    if (moduleName === lower || modulePath.endsWith('\\\\' + lower) || modulePath.endsWith('/' + lower)) {{
      return modules[i].base;
    }}
  }}
  return null;
}}

function isNullPtr(value) {{
  return value === null || value.toString() === '0x0';
}}

if (typeof Process.attachModuleObserver === 'function') {{
  Process.attachModuleObserver({{
    onAdded(module) {{
      const lower = moduleName.toLowerCase();
      const moduleLower = module.name.toLowerCase();
      const pathLower = module.path.toLowerCase();
      if (moduleLower === lower || pathLower.endsWith('\\\\' + lower) || pathLower.endsWith('/' + lower)) {{
        installHookForBase(module.base);
      }}
    }}
  }});
}}

setImmediate(installHook);
"""


def is_printable_ascii(text: str) -> bool:
    return all(32 <= ord(ch) <= 126 for ch in text)


def hook_key_with_frida(
    qq_exe: Path,
    function_rva: int,
    timeout: float,
    pid: int | None,
    accept_lengths: set[int],
    attach_running: bool,
    spawn_even_if_running: bool,
    spawn_gating: bool,
    quiet_qq_logs: bool,
    kill_spawned_on_timeout: bool,
) -> HookResult:
    try:
        import frida
    except ImportError as exc:
        raise ScriptError("Frida 后端需要 Python 包 frida：python -m pip install frida") from exc

    device = frida.get_local_device()
    script_source = make_frida_script(function_rva)
    found = threading.Event()
    result: HookResult | None = None
    sessions = []
    attached_pids: set[int] = set()
    failed_pids: set[int] = set()
    spawned_pids: set[int] = set()
    gating_enabled = False

    def on_message(source_pid: int, message, data) -> None:
        nonlocal result
        if message.get("type") == "error":
            print(f"[frida:{source_pid}] {message.get('description')}", file=sys.stderr, flush=True)
            return

        payload = message.get("payload")
        if not isinstance(payload, dict):
            return

        event_type = payload.get("type")
        if event_type == "hook-installed":
            print(f"[frida:{source_pid}] 已安装 hook: {payload.get('target')}", flush=True)
            return
        if event_type != "key":
            return

        raw = bytes(data or b"")
        text = payload.get("keyText") or raw.split(b"\x00", 1)[0].decode("ascii", "replace")
        text = text.split("\x00", 1)[0]
        n_key = int(payload.get("nKey") or len(raw))

        if n_key not in accept_lengths or len(text) not in accept_lengths or not is_printable_ascii(text):
            print(f"[frida:{source_pid}] 忽略候选 key: len={n_key} text={text!r}", flush=True)
            return

        result = HookResult(
            key=text,
            raw_hex=raw.hex(),
            n_key=n_key,
            z_db=str(payload.get("zDb") or ""),
            pid=source_pid,
            base=payload.get("base"),
            target=payload.get("target"),
        )
        found.set()

    def attach_to(target_pid: int) -> None:
        if target_pid in attached_pids or target_pid in failed_pids:
            return
        session = device.attach(target_pid)
        script = session.create_script(script_source)
        script.on("message", lambda msg, data, source_pid=target_pid: on_message(source_pid, msg, data))
        script.load()
        sessions.append(session)
        attached_pids.add(target_pid)

    def attach_all_qq_processes() -> None:
        for proc in find_qq_processes(device):
            if proc.pid in attached_pids or proc.pid in failed_pids:
                continue
            try:
                print(f"[*] 正在附加 QQ.exe PID {proc.pid}", flush=True)
                attach_to(proc.pid)
            except Exception as exc:  # Frida can fail on short-lived helper processes.
                failed_pids.add(proc.pid)
                print(f"[!] 附加 PID {proc.pid} 失败: {exc}", flush=True)

    def on_spawn_added(spawn) -> None:
        spawn_pid = int(spawn.pid)
        identifier = str(getattr(spawn, "identifier", "") or "")
        spawned_pids.add(spawn_pid)
        try:
            if identifier.lower().endswith("qq.exe") or identifier.lower() == "qq.exe":
                print(f"[*] 捕获 QQ 子进程 PID {spawn_pid}，先注入 hook 再恢复。", flush=True)
                attach_to(spawn_pid)
            device.resume(spawn_pid)
        except Exception as exc:
            failed_pids.add(spawn_pid)
            print(f"[!] 处理子进程 PID {spawn_pid} 失败: {exc}", flush=True)
            try:
                device.resume(spawn_pid)
            except Exception:
                pass

    try:
        if pid is not None:
            print(f"[*] 正在附加指定 QQ.exe PID {pid}", flush=True)
            attach_to(pid)
        else:
            running = find_qq_processes(device)
            if running and attach_running:
                print("[*] QQ.exe 已在运行，正在附加所有 QQ 进程。", flush=True)
                attach_all_qq_processes()
            else:
                if running and not spawn_even_if_running:
                    pids = ", ".join(str(proc.pid) for proc in running)
                    raise ScriptError(
                        "QQ.exe 已经在运行，当前会话可能已经错过 key。"
                        f"运行中的 PID: {pids}。请使用 --attach-running，或完全退出 QQ 后重试。"
                    )
                if spawn_gating:
                    try:
                        device.on("spawn-added", on_spawn_added)
                        device.enable_spawn_gating()
                        gating_enabled = True
                        print("[*] 已开启 Frida spawn gating，用于抢先注入 QQ 子进程。", flush=True)
                    except Exception as exc:
                        print(f"[!] 当前 Frida 本地设备不支持 spawn gating，降级为轮询附加：{exc}", flush=True)
                        gating_enabled = False

                print(f"[*] 正在启动 QQ: {qq_exe}", flush=True)
                with quiet_child_stdio(quiet_qq_logs):
                    spawned_pid = device.spawn([str(qq_exe)])
                spawned_pids.add(spawned_pid)
                print(f"[*] 已创建挂起进程 PID {spawned_pid}，先安装 hook 再恢复运行。", flush=True)
                attach_to(spawned_pid)
                with quiet_child_stdio(quiet_qq_logs):
                    device.resume(spawned_pid)
                print("[*] QQ 已恢复运行；如出现登录界面，请登录以触发数据库打开。", flush=True)

        deadline = time.time() + timeout
        while time.time() < deadline and not found.is_set():
            if pid is None:
                attach_all_qq_processes()
            time.sleep(0.5)

        if result is None:
            if kill_spawned_on_timeout and spawned_pids:
                print("[*] 未抓到 key，正在结束本次启动的 QQ 进程。", flush=True)
                kill_qq_processes()
            raise ScriptError("等待 QQ NT 数据库 key 超时。请完全退出 QQ 后重试，或在 QQ 界面触发登录/打开聊天。")
        return result
    finally:
        if gating_enabled:
            try:
                device.disable_spawn_gating()
            except Exception:
                pass
        for session in sessions:
            try:
                session.detach()
            except Exception:
                pass


@contextmanager
def quiet_child_stdio(enabled: bool):
    if not enabled:
        yield
        return
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    saved_stdout = os.dup(1)
    saved_stderr = os.dup(2)
    try:
        os.dup2(devnull_fd, 1)
        os.dup2(devnull_fd, 2)
        yield
    finally:
        os.dup2(saved_stdout, 1)
        os.dup2(saved_stderr, 2)
        os.close(saved_stdout)
        os.close(saved_stderr)
        os.close(devnull_fd)


def kill_qq_processes() -> None:
    subprocess.run(
        ["taskkill", "/IM", "QQ.exe", "/F", "/T"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def last_win_error(message: str) -> ScriptError:
    return ScriptError(f"{message}: WinError {ctypes.get_last_error()}")


def debug_event_exception_code(event: DEBUG_EVENT) -> int:
    return struct.unpack_from("<I", bytes(event.u), 0)[0]


def debug_event_exception_address(event: DEBUG_EVENT) -> int:
    return struct.unpack_from("<Q", bytes(event.u), 16)[0]


def debug_event_file_handle(event: DEBUG_EVENT) -> int:
    return struct.unpack_from("<q", bytes(event.u), 0)[0]


def read_process_memory(handle: HANDLE, address: int, size: int) -> bytes:
    buffer = (BYTE * size)()
    read = SIZE_T(0)
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(read))
    if not ok:
        raise last_win_error(f"读取进程内存失败: 0x{address:X}")
    return bytes(buffer[: read.value])


def write_process_memory(handle: HANDLE, address: int, data: bytes) -> None:
    buffer = ctypes.create_string_buffer(data)
    written = SIZE_T(0)
    ok = kernel32.WriteProcessMemory(handle, ctypes.c_void_p(address), buffer, len(data), ctypes.byref(written))
    if not ok or written.value != len(data):
        raise last_win_error(f"写入进程内存失败: 0x{address:X}")
    kernel32.FlushInstructionCache(handle, ctypes.c_void_p(address), len(data))


def enum_process_modules(pid: int) -> list[tuple[str, str, int]]:
    modules: list[tuple[str, str, int]] = []
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if int(snapshot) == -1:
        return modules
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        ok = kernel32.Module32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            modules.append((entry.szModule, entry.szExePath, ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0))
            ok = kernel32.Module32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return modules


def find_module_base_in_process(pid: int, module_name: str) -> int | None:
    lower = module_name.lower()
    for name, path, base in enum_process_modules(pid):
        if name.lower() == lower or path.lower().endswith("\\" + lower) or path.lower().endswith("/" + lower):
            return base
    return None


def is_valid_key_text(text: str, accept_lengths: set[int]) -> bool:
    return len(text) in accept_lengths and is_printable_ascii(text)


def capture_key_with_debugger(
    qq_exe: Path,
    function_rva: int,
    timeout: float,
    accept_lengths: set[int],
    keep_qq_after_key: bool,
) -> HookResult:
    startup = STARTUPINFOW()
    startup.cb = ctypes.sizeof(STARTUPINFOW)
    process_info = PROCESS_INFORMATION()
    command_line = ctypes.create_unicode_buffer(f'"{qq_exe}"')

    print(f"[*] 正在以 Windows 调试器方式启动 QQ: {qq_exe}", flush=True)
    ok = kernel32.CreateProcessW(
        str(qq_exe),
        command_line,
        None,
        None,
        False,
        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_PROCESS_GROUP,
        None,
        str(qq_exe.parent),
        ctypes.byref(startup),
        ctypes.byref(process_info),
    )
    if not ok:
        raise last_win_error("启动 QQ 调试进程失败")

    h_process = process_info.hProcess
    pid = int(process_info.dwProcessId)
    breakpoint_addr: int | None = None
    original_byte: bytes | None = None
    stepping_threads: set[int] = set()
    deadline = time.time() + timeout

    def set_breakpoint(wrapper_base: int) -> None:
        nonlocal breakpoint_addr, original_byte
        if breakpoint_addr is not None:
            return
        breakpoint_addr = wrapper_base + function_rva
        original_byte = read_process_memory(h_process, breakpoint_addr, 1)
        write_process_memory(h_process, breakpoint_addr, b"\xCC")
        print(f"[*] wrapper.node 基址: 0x{wrapper_base:X}", flush=True)
        print(f"[*] 已在 key 函数入口下断点: 0x{breakpoint_addr:X}", flush=True)

    def restore_breakpoint_byte() -> None:
        if breakpoint_addr is not None and original_byte is not None:
            write_process_memory(h_process, breakpoint_addr, original_byte)

    def reinstall_breakpoint() -> None:
        if breakpoint_addr is not None:
            write_process_memory(h_process, breakpoint_addr, b"\xCC")

    def read_key_from_thread(thread_id: int) -> HookResult | None:
        if breakpoint_addr is None:
            return None
        restore_breakpoint_byte()
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, thread_id)
        if not h_thread:
            print(f"[!] 打开线程 {thread_id} 失败，跳过本次断点。", flush=True)
            return None
        try:
            ctx = CONTEXT64()
            ctx.ContextFlags = CONTEXT_CONTROL_INTEGER
            if not kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
                print(f"[!] 获取线程 {thread_id} 上下文失败。", flush=True)
                return None
            ctx.Rip = breakpoint_addr
            p_key = int(ctx.R8)
            n_key = int(ctx.R9 & 0xFFFFFFFF)
            if n_key <= 0 or n_key > 512:
                n_key = max(accept_lengths)
            try:
                raw = read_process_memory(h_process, p_key, min(max(n_key, max(accept_lengths)), 256))
            except ScriptError:
                raw = b""
            text = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
            if is_valid_key_text(text, accept_lengths):
                print(f"[*] 命中有效 key，长度 {len(text)}。", flush=True)
                return HookResult(
                    key=text,
                    raw_hex=raw[: len(text)].hex(),
                    n_key=len(text),
                    z_db="",
                    pid=pid,
                    base=None,
                    target=f"0x{breakpoint_addr:X}",
                )

            preview = text[:40]
            print(f"[*] 忽略非目标断点，R8 文本={preview!r} 长度={len(text)}。", flush=True)
            ctx.EFlags |= 0x100
            if not kernel32.SetThreadContext(h_thread, ctypes.byref(ctx)):
                print(f"[!] 设置单步上下文失败。", flush=True)
            else:
                stepping_threads.add(thread_id)
            return None
        finally:
            kernel32.CloseHandle(h_thread)

    result: HookResult | None = None
    event = DEBUG_EVENT()
    try:
        while time.time() < deadline and result is None:
            wait_ms = max(1, min(500, int((deadline - time.time()) * 1000)))
            if not kernel32.WaitForDebugEvent(ctypes.byref(event), wait_ms):
                continue

            continue_status = DBG_CONTINUE
            code = int(event.dwDebugEventCode)
            event_pid = int(event.dwProcessId)
            event_tid = int(event.dwThreadId)
            try:
                if code in (CREATE_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT):
                    file_handle = debug_event_file_handle(event)
                    if file_handle:
                        kernel32.CloseHandle(HANDLE(file_handle))
                    wrapper_base = find_module_base_in_process(pid, "wrapper.node")
                    if wrapper_base is not None:
                        set_breakpoint(wrapper_base)

                elif code == EXCEPTION_DEBUG_EVENT:
                    exception_code = debug_event_exception_code(event)
                    exception_addr = debug_event_exception_address(event)
                    if exception_code == EXCEPTION_BREAKPOINT:
                        if breakpoint_addr is not None and exception_addr == breakpoint_addr:
                            result = read_key_from_thread(event_tid)
                            if result is not None:
                                continue_status = DBG_CONTINUE
                            else:
                                continue_status = DBG_CONTINUE
                        else:
                            continue_status = DBG_CONTINUE
                    elif exception_code == EXCEPTION_SINGLE_STEP and event_tid in stepping_threads:
                        stepping_threads.remove(event_tid)
                        reinstall_breakpoint()
                        continue_status = DBG_CONTINUE
                    else:
                        continue_status = DBG_EXCEPTION_NOT_HANDLED

                elif code == EXIT_PROCESS_DEBUG_EVENT:
                    raise ScriptError("QQ 调试进程已退出，未捕获到 key。")
            finally:
                kernel32.ContinueDebugEvent(event_pid, event_tid, continue_status)

        if result is None:
            raise ScriptError("Windows 调试器等待 key 超时。请确认 QQ 已触发登录/数据库打开。")
        return result
    finally:
        try:
            if result is not None and keep_qq_after_key:
                restore_breakpoint_byte()
            else:
                kernel32.TerminateProcess(h_process, 0)
        finally:
            kernel32.CloseHandle(process_info.hThread)
            kernel32.CloseHandle(process_info.hProcess)


def shell_quote_sql(value: str) -> str:
    return value.replace("'", "''")


def strip_qq_database_header(encrypted_db: Path, stripped_db: Path) -> None:
    """去掉 QQ NT 数据库前 1024 字节的 plaintext header。"""
    stripped_db.parent.mkdir(parents=True, exist_ok=True)
    with encrypted_db.open("rb") as source, stripped_db.open("wb") as destination:
        source.seek(1024)
        shutil.copyfileobj(source, destination)


def resolve_sqlcipher(preferred: str | None) -> str | None:
    if preferred:
        candidate = Path(preferred).expanduser()
        if candidate.is_file():
            return str(candidate)
        resolved = shutil.which(preferred)
        if resolved:
            return resolved
        return None

    env_value = os.environ.get("SQLCIPHER")
    if env_value:
        candidate = Path(env_value).expanduser()
        if candidate.is_file():
            return str(candidate)

    for name in ("sqlcipher", "sqlcipher.exe", "sqlcipher-x64.exe"):
        resolved = shutil.which(name)
        if resolved:
            return resolved
    return None


def load_pysqlcipher3():
    try:
        from pysqlcipher3 import dbapi2 as sqlcipher
    except ImportError as exc:
        raise ScriptError(
            "当前 Python 环境未安装 rotki-pysqlcipher3。"
            "可在 Python 3.11/3.12 环境执行：python -m pip install rotki-pysqlcipher3"
        ) from exc
    return sqlcipher


def has_pysqlcipher3() -> bool:
    try:
        load_pysqlcipher3()
    except ScriptError:
        return False
    return True


def choose_decrypt_backend(requested: str, sqlcipher_arg: str | None) -> tuple[str, str | None]:
    if requested == "python":
        load_pysqlcipher3()
        return "python", None

    if requested == "cli":
        sqlcipher_exe = resolve_sqlcipher(sqlcipher_arg)
        if not sqlcipher_exe:
            raise_sqlcipher_not_found()
        return "cli", sqlcipher_exe

    if has_pysqlcipher3():
        return "python", None

    sqlcipher_exe = resolve_sqlcipher(sqlcipher_arg)
    if sqlcipher_exe:
        return "cli", sqlcipher_exe

    raise ScriptError(
        "未找到可用解密后端。优先方案：在 Python 3.11/3.12 环境安装 rotki-pysqlcipher3；"
        "备用方案：下载 SQLCipher CLI，并用 --sqlcipher 指定真实路径。"
        "QQBackup 提供的 Win64 CLI 可从 "
        "https://github.com/QQBackup/sqlcipher-github-actions/releases/latest 下载。"
    )


def raise_sqlcipher_not_found() -> None:
    raise ScriptError(
        "未找到 sqlcipher 可执行文件。请下载 SQLCipher CLI，并用 --sqlcipher 指定真实路径；"
        "不要直接复制 README 里的占位路径。"
        "QQBackup 提供的 Win64 版本可从 "
        "https://github.com/QQBackup/sqlcipher-github-actions/releases/latest 下载。"
    )


def apply_qq_sqlcipher_pragmas(cursor, key: str) -> None:
    cursor.execute(f"PRAGMA key = '{shell_quote_sql(key)}';")
    cursor.execute("PRAGMA cipher_page_size = 4096;")
    cursor.execute("PRAGMA kdf_iter = 4000;")
    cursor.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1;")
    cursor.execute("PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512;")


def export_with_sqlcipher(sqlcipher: str, encrypted_db: Path, plaintext_db: Path, key: str) -> None:
    plaintext_db.parent.mkdir(parents=True, exist_ok=True)
    if plaintext_db.exists():
        plaintext_db.unlink()

    sql = "\n".join(
        [
            f"PRAGMA key = '{shell_quote_sql(key)}';",
            "PRAGMA cipher_page_size = 4096;",
            "PRAGMA kdf_iter = 4000;",
            "PRAGMA cipher_hmac_algorithm = HMAC_SHA1;",
            "PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512;",
            f"ATTACH DATABASE '{shell_quote_sql(str(plaintext_db))}' AS plaintext KEY '';",
            "SELECT sqlcipher_export('plaintext');",
            "DETACH DATABASE plaintext;",
            ".quit",
            "",
        ]
    )
    try:
        proc = subprocess.run(
            [sqlcipher, str(encrypted_db)],
            input=sql,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise ScriptError(f"无法运行 SQLCipher: {sqlcipher}。请确认 --sqlcipher 指向真实存在的 exe 文件。") from exc
    if proc.returncode != 0:
        raise ScriptError(f"sqlcipher 执行失败，退出码 {proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}")


def export_with_pysqlcipher3(encrypted_db: Path, plaintext_db: Path, key: str) -> None:
    sqlcipher = load_pysqlcipher3()
    plaintext_db.parent.mkdir(parents=True, exist_ok=True)
    if plaintext_db.exists():
        plaintext_db.unlink()

    con = sqlcipher.connect(str(encrypted_db))
    try:
        cur = con.cursor()
        apply_qq_sqlcipher_pragmas(cur, key)
        cur.execute(f"ATTACH DATABASE '{shell_quote_sql(str(plaintext_db))}' AS plaintext KEY '';")
        cur.execute("SELECT sqlcipher_export('plaintext');")
        cur.execute("DETACH DATABASE plaintext;")
    finally:
        con.close()


def run_self_message_extractor(plaintext_db: Path, account: str, outdir: Path) -> None:
    extractor = Path(__file__).with_name("qqnt_extract_self_messages.py")
    if not extractor.exists():
        raise ScriptError(f"未找到提取脚本: {extractor}")
    cmd = [
        sys.executable,
        str(extractor),
        "--db",
        str(plaintext_db),
        "--account",
        str(account),
        "--outdir",
        str(outdir),
        "--quiet",
    ]
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.stdout.strip():
        print(proc.stdout.strip())
    if proc.returncode != 0:
        raise ScriptError(f"提取本人消息失败: {proc.stderr.strip() or proc.stdout.strip()}")


def parse_accept_lengths(value: str) -> set[int]:
    lengths = {int(part.strip()) for part in value.split(",") if part.strip()}
    if not lengths:
        raise argparse.ArgumentTypeError("at least one length is required")
    return lengths


def write_summary(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="获取 Windows QQ NT 数据库 key，并复制 nt_msg.db。")
    parser.add_argument("--backend", choices=("debugger", "frida"), default="debugger", help="运行时抓 key 后端，默认 debugger。")
    parser.add_argument("--qq-exe", help="QQ.exe 路径，默认自动检测。")
    parser.add_argument("--wrapper", help="wrapper.node 路径，默认自动检测。")
    parser.add_argument("--pid", type=int, help="Frida 后端：附加到指定 QQ.exe PID。")
    parser.add_argument("--attach-running", action="store_true", help="Frida 后端：附加所有正在运行的 QQ.exe。")
    parser.add_argument("--spawn-even-if-running", action="store_true", help="Frida 后端：即使 QQ 已运行，也再启动一个 QQ。")
    parser.add_argument("--kill-qq-first", action="store_true", help="启动前先强制结束所有 QQ.exe。")
    parser.add_argument("--no-spawn-gating", action="store_true", help="Frida 后端：禁用子进程 spawn gating。")
    parser.add_argument("--show-qq-logs", action="store_true", help="Frida 后端：显示 QQ 自身启动日志。")
    parser.add_argument("--keep-qq-on-timeout", action="store_true", help="Frida 后端：超时后不结束本次启动的 QQ。")
    parser.add_argument("--keep-qq-after-key", action="store_true", help="debugger 后端：抓到 key 后保留 QQ 继续运行。")
    parser.add_argument("--static-only", action="store_true", help="只输出静态定位 RVA，不启动 QQ。")
    parser.add_argument("--account", help="QQ 号，用于定位 Documents/Tencent Files/<QQ号>/nt_qq/nt_db。")
    parser.add_argument("--db-dir", help="包含 nt_msg.db 的目录；不传时尽量自动检测。")
    parser.add_argument("--db-name", default=DEFAULT_DB_BASENAME, help="要复制的数据库文件名，默认 nt_msg.db。")
    parser.add_argument("--outdir", default="RE/windows_qq_export", help="key 摘要、数据库和提取结果输出目录。")
    parser.add_argument("--no-copy-db", action="store_true", help="只抓 key，不复制数据库文件。")
    parser.add_argument("--timeout", type=float, default=180.0, help="等待 key 的秒数，默认 180。")
    parser.add_argument("--accept-key-lengths", type=parse_accept_lengths, default={16}, help="接受的 key 长度，逗号分隔，默认 16。")
    parser.add_argument("--no-decrypt", action="store_true", help="跳过 SQLCipher 自动解密。")
    parser.add_argument(
        "--decrypt-backend",
        choices=("auto", "python", "cli"),
        default="auto",
        help="解密后端：auto 优先 rotki-pysqlcipher3，失败则用 CLI；python 强制 pysqlcipher3；cli 强制 SQLCipher CLI。",
    )
    parser.add_argument("--export-plaintext", action="store_true", help="兼容旧参数；当前默认会自动解密。")
    parser.add_argument("--sqlcipher", nargs="?", const="sqlcipher", help="SQLCipher 可执行文件路径或命令名。")
    parser.add_argument("--plaintext-db", help="明文数据库输出路径，默认 <outdir>/nt_msg_plaintext.db。")
    parser.add_argument("--no-extract", action="store_true", help="跳过本人消息提取。")
    parser.add_argument("--extract-outdir", help="本人消息提取输出目录，默认 <outdir>/qq_export。")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if os.name != "nt":
        raise ScriptError("此脚本仅支持 Windows。")

    install = detect_qq_install(args.qq_exe, args.wrapper)
    candidate = find_key_function(install.wrapper_node)

    print(f"QQ 主程序:        {install.qq_exe}")
    print(f"QQ 版本:          {install.version or '未知'}")
    print(f"wrapper.node:    {install.wrapper_node}")
    print(f"目标字符串 RVA:   0x{candidate.string_rva:X}")
    print(f"LEA 指令 RVA:     0x{candidate.lea_rva:X}")
    print(f"key 函数 RVA:     0x{candidate.function_rva:X}")

    if args.static_only:
        return 0

    outdir = Path(args.outdir).expanduser()
    outdir.mkdir(parents=True, exist_ok=True)

    will_decrypt = not args.no_decrypt and not args.no_copy_db
    decrypt_backend = None
    sqlcipher_exe = None
    if will_decrypt:
        decrypt_backend, sqlcipher_exe = choose_decrypt_backend(args.decrypt_backend, args.sqlcipher)

    if args.kill_qq_first and args.pid is None and not args.attach_running:
        print("[*] 正在结束已有 QQ.exe 进程。", flush=True)
        kill_qq_processes()
        time.sleep(2)

    if args.backend == "debugger":
        if args.pid or args.attach_running:
            raise ScriptError("debugger 后端需要自行启动 QQ，不能与 --pid 或 --attach-running 同用。")
        hook_result = capture_key_with_debugger(
            qq_exe=install.qq_exe,
            function_rva=candidate.function_rva,
            timeout=args.timeout,
            accept_lengths=args.accept_key_lengths,
            keep_qq_after_key=args.keep_qq_after_key,
        )
    else:
        hook_result = hook_key_with_frida(
            qq_exe=install.qq_exe,
            function_rva=candidate.function_rva,
            timeout=args.timeout,
            pid=args.pid,
            accept_lengths=args.accept_key_lengths,
            attach_running=args.attach_running,
            spawn_even_if_running=args.spawn_even_if_running,
            spawn_gating=not args.no_spawn_gating,
            quiet_qq_logs=not args.show_qq_logs,
            kill_spawned_on_timeout=not args.keep_qq_on_timeout,
        )

    print("")
    print("=" * 48)
    print(f"QQ NT 数据库 key: {hook_result.key}")
    print("=" * 48)

    copied: list[Path] = []
    db_dir: Path | None = None
    if not args.no_copy_db:
        db_dir = Path(args.db_dir).expanduser() if args.db_dir else find_default_db_dir(args.account, args.db_name)
        if db_dir is None:
            raise ScriptError("未能定位 nt_db 目录，请使用 --account 或 --db-dir。")
        copied = copy_db_bundle(db_dir, outdir, args.db_name)
        if not copied:
            raise ScriptError(f"没有从 {db_dir} 复制到任何数据库文件")
        print(f"已复制 {len(copied)} 个文件到 {outdir}")

    plaintext_db = None
    stripped_db = None
    extract_outdir = None
    if not args.no_decrypt and not args.no_copy_db:
        encrypted_db = outdir / args.db_name
        stripped_db = outdir / f"{Path(args.db_name).stem}.sqlcipher.db"
        plaintext_db = Path(args.plaintext_db).expanduser() if args.plaintext_db else outdir / "nt_msg_plaintext.db"
        print("[*] 正在移除 QQ NT 数据库前 1024 字节 header。")
        strip_qq_database_header(encrypted_db, stripped_db)
        print(f"已生成 SQLCipher 输入库: {stripped_db}")
        if decrypt_backend == "python":
            print("[*] 正在使用 rotki-pysqlcipher3 导出明文 SQLite 数据库。")
            export_with_pysqlcipher3(stripped_db, plaintext_db, hook_result.key)
        else:
            print("[*] 正在使用 SQLCipher CLI 导出明文 SQLite 数据库。")
            export_with_sqlcipher(str(sqlcipher_exe), stripped_db, plaintext_db, hook_result.key)
        print(f"明文数据库已导出到 {plaintext_db}")

        if not args.no_extract and args.account:
            extract_outdir = Path(args.extract_outdir).expanduser() if args.extract_outdir else outdir / "qq_export"
            print("[*] 正在从明文库提取本人消息。")
            run_self_message_extractor(plaintext_db, args.account, extract_outdir)
        elif not args.no_extract:
            print("[!] 未提供 --account，已跳过本人消息提取。")

    summary = {
        "qq_version": install.version,
        "qq_exe": str(install.qq_exe),
        "wrapper_node": str(install.wrapper_node),
        "string_rva": f"0x{candidate.string_rva:X}",
        "lea_rva": f"0x{candidate.lea_rva:X}",
        "function_rva": f"0x{candidate.function_rva:X}",
        "pid": hook_result.pid,
        "z_db": hook_result.z_db,
        "n_key": hook_result.n_key,
        "key": hook_result.key,
        "db_dir": str(db_dir) if db_dir else None,
        "copied_files": [str(path) for path in copied],
        "stripped_db": str(stripped_db) if stripped_db else None,
        "plaintext_db": str(plaintext_db) if plaintext_db else None,
        "decrypt_backend": decrypt_backend,
        "sqlcipher": str(sqlcipher_exe) if sqlcipher_exe else None,
        "extract_outdir": str(extract_outdir) if extract_outdir else None,
    }
    write_summary(outdir / "windows_qq_key_summary.json", summary)
    print(f"摘要已写入 {outdir / 'windows_qq_key_summary.json'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ScriptError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        raise SystemExit(1)

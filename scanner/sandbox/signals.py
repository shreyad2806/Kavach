"""
Sandbox signal definitions.

Maps patterns found in container output to SandboxEventType.
Each entry is a (pattern, event_type, suspicious) tuple.
Patterns are matched against each line of container stdout/stderr.
Order matters — first match wins per line.
"""

import re
from dataclasses import dataclass

from scanner.models.sandbox import SandboxEventType


@dataclass(frozen=True)
class Signal:
    pattern: re.Pattern
    event_type: SandboxEventType
    suspicious: bool


# Suspicious paths that indicate secret/credential access attempts
_SECRET_PATHS = (
    r"/etc/passwd", r"/etc/shadow", r"/etc/hosts",
    r"\.aws/credentials", r"\.ssh/", r"/proc/",
    r"AWS_SECRET", r"AWS_ACCESS_KEY", r"api_key", r"private_key",
)

SIGNALS: list[Signal] = [
    # Network
    Signal(re.compile(r"connect\(.*\d+\.\d+\.\d+\.\d+", re.I), SandboxEventType.NETWORK_CONNECT, True),
    Signal(re.compile(r"(urllib|requests|http\.client|socket).*connect", re.I), SandboxEventType.NETWORK_CONNECT, True),
    Signal(re.compile(r"dns|gethostbyname|getaddrinfo", re.I), SandboxEventType.DNS_LOOKUP, False),
    Signal(re.compile(r"(wget|curl|urllib\.request|requests\.get|download)", re.I), SandboxEventType.UNEXPECTED_DOWNLOAD, True),

    # Secrets / credentials
    Signal(re.compile("|".join(_SECRET_PATHS), re.I), SandboxEventType.SECRET_ACCESS, True),
    Signal(re.compile(r"os\.environ|getenv|environ\[", re.I), SandboxEventType.ENV_READ, False),

    # Process / shell
    Signal(re.compile(r"(require\(['\"]child_process['\"]|execSync|execFile|spawnSync)", re.I), SandboxEventType.SHELL_EXECUTION, True),
    Signal(re.compile(r"(subprocess|os\.system|os\.popen|shell=True|/bin/sh|/bin/bash)", re.I), SandboxEventType.SHELL_EXECUTION, True),
    Signal(re.compile(r"(Popen|exec|execve|fork\(\))", re.I), SandboxEventType.PROCESS_SPAWN, True),
    Signal(re.compile(r"(setuid|setgid|chmod\s*777|sudo|privilege)", re.I), SandboxEventType.PRIVILEGE_ESCALATION, True),

    # Filesystem
    Signal(re.compile(r"open\(.*['\"]w['\"]|write\(|\.write\(", re.I), SandboxEventType.FILE_WRITE, False),
    Signal(re.compile(r"(os\.remove|os\.unlink|shutil\.rmtree|unlink\()", re.I), SandboxEventType.FILE_DELETE, True),
    Signal(re.compile(r"open\(.*['\"]r['\"]|\.read\(|readlines\(", re.I), SandboxEventType.FILE_READ, False),

    # Strace syscall patterns
    Signal(re.compile(r"connect\(.*AF_INET", re.I), SandboxEventType.NETWORK_CONNECT, True),
    Signal(re.compile(r"execve\(", re.I), SandboxEventType.PROCESS_SPAWN, True),
    Signal(re.compile(r"openat\(.*O_WRONLY|openat\(.*O_RDWR", re.I), SandboxEventType.FILE_WRITE, False),
    Signal(re.compile(r"unlinkat?\(", re.I), SandboxEventType.FILE_DELETE, True),
    Signal(re.compile(r"setuid|setgid|setreuid|setregid", re.I), SandboxEventType.PRIVILEGE_ESCALATION, True),

    # Node.js-specific patterns
    Signal(re.compile(r"(https?|axios|fetch|node-fetch|got)\.(get|post|request)", re.I), SandboxEventType.NETWORK_CONNECT, True),
    Signal(re.compile(r"(fs\.writeFile|fs\.appendFile|createWriteStream)", re.I), SandboxEventType.FILE_WRITE, False),
    Signal(re.compile(r"(fs\.unlink|rimraf)", re.I), SandboxEventType.FILE_DELETE, True),
    Signal(re.compile(r"process\.env", re.I), SandboxEventType.ENV_READ, False),
]

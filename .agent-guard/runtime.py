#!/usr/bin/python3 -I
"""Host executor. Install reviewed bytes outside the checkout; never run as a hook from it.

The Docker daemon and registered image are trusted. Requests cannot select mounts,
environment, runtime, image or host commands. Only disposable source copies execute.
"""
import argparse
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

DOCKER = "/usr/bin/docker"
REGISTRY = Path("/etc/agent-guard/repositories.json")
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
MAX_FILES = 10000
DENIED = {".git", ".ssh", ".aws", ".gnupg", ".config", ".docker"}


class Refused(Exception):
    pass


def protected_install(path):
    """No symlink or worker-writable ancestor, including the installed executable."""
    path = Path(path).absolute()
    for part in [*reversed(path.parents), path]:
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused(f"untrusted host installation: {part}")
    return path


def output_patterns():
    """Patterns are installed with the trusted runtime, never read from the checkout."""
    try:
        path = protected_install(Path(__file__).with_name("patterns.json"))
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024 * 1024:
            raise Refused("invalid trusted output policy")
        rules = json.loads(path.read_text())["patterns"]
        if not isinstance(rules, list) or not rules:
            raise Refused("missing trusted output policy")
        compiled = []
        for rule in rules:
            flags = re.I
            for flag in rule.get("flags", ""):
                if flag not in "ms":
                    raise Refused("invalid trusted output policy")
                flags |= re.M if flag == "m" else re.S
            compiled.append(re.compile(rule["rx"], flags))
        return compiled
    except (OSError, KeyError, TypeError, ValueError, re.error) as error:
        raise Refused("trusted output policy unavailable") from error


def checked_output(value):
    """Quarantine matched output before it reaches any client; emit no matched snippets."""
    patterns = output_patterns()
    remaining = MAX_OUTPUT
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            remaining -= len(item.encode("utf-8"))
            if remaining < 0:
                raise Refused("output size limit exceeded")
            if any(pattern.search(item) for pattern in patterns):
                raise Refused("output quarantined by trusted content policy")
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
    return value


def matches(name, patterns):
    # Match both an object and the subtree selected by directory/** policies.
    return any(fnmatch.fnmatchcase(name, p) or fnmatch.fnmatchcase(name, p.replace("**/", ""))
               or (p.endswith("/**") and name == p[:-3]) for p in patterns)


def excluded(name, policy):
    parts = Path(name).parts
    return (any(p in DENIED for p in parts)
            or matches(name, ["**/.env", "**/.env.*", "**/*.key", "**/*.pem", "**/*.p12",
                              "**/.npmrc", "**/.netrc", "**/.pypirc", "**/*credentials*.json",
                              "**/*service-account*.json"])
            or matches(name, policy["secret_paths"])
            or (matches(name, policy["quarantine_paths"])
                and not matches(name, policy.get("quarantine_exempt", []))))


def snapshot(root, policy):
    """Descriptor-relative copy: no source symlinks, hardlinks or special files.

    Returns an archive made by us, never an archive from repository code. No
    secret/excluded file is opened. A concurrent source change aborts the snapshot.
    """
    files = {}
    total = 0
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    rootfd = os.open(root, flags | os.O_DIRECTORY)
    device = os.fstat(rootfd).st_dev

    def walk(fd, prefix=""):
        nonlocal total
        before = os.fstat(fd)
        for entry in sorted(os.listdir(fd)):
            name = f"{prefix}/{entry}" if prefix else entry
            if excluded(name, policy):
                continue
            info = os.stat(entry, dir_fd=fd, follow_symlinks=False)
            if info.st_dev != device or stat.S_ISLNK(info.st_mode):
                raise Refused(f"link or mount in snapshot: {name}")
            child = os.open(entry, flags | os.O_NONBLOCK, dir_fd=fd)
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise Refused(f"source changed: {name}")
                if stat.S_ISDIR(opened.st_mode):
                    walk(child, name)
                elif stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1:
                    if opened.st_size > MAX_FILE or len(files) >= MAX_FILES:
                        raise Refused("snapshot size limit exceeded")
                    chunks = []
                    size = 0
                    while True:
                        chunk = os.read(child, min(65536, MAX_FILE + 1 - size))
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_FILE:
                            raise Refused("snapshot file grew beyond limit")
                        chunks.append(chunk)
                    after = os.fstat(child)
                    if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise Refused(f"source changed during read: {name}")
                    data = b"".join(chunks)
                    total += len(data)
                    if total > MAX_TOTAL:
                        raise Refused("snapshot total size exceeded")
                    files[name] = (data, 0o755 if opened.st_mode & 0o111 else 0o644)
                else:
                    raise Refused(f"nonregular or hardlinked source: {name}")
            finally:
                os.close(child)
        after = os.fstat(fd)
        if (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
            raise Refused("source directory changed during snapshot")

    try:
        walk(rootfd)
    finally:
        os.close(rootfd)
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        for name, (data, mode) in files.items():
            item = tarfile.TarInfo("input/" + name)
            item.size, item.mode, item.uid, item.gid = len(data), mode, 0, 0
            tar.addfile(item, io.BytesIO(data))
    return archive.getvalue(), files


BOOT = r'''
import hashlib, json, os, pathlib, shutil, stat, subprocess, sys
request = json.load(sys.stdin)
protected = request.get('protected', [])
for directory, dirs, files in os.walk('/input'):
    relative = pathlib.Path(directory).relative_to('/input')
    dirs[:] = [d for d in dirs if str(relative / d) not in protected]
    target = pathlib.Path('/work/source', relative)
    target.mkdir(parents=True, exist_ok=True)
    for name in files:
        if str(relative / name) not in protected:
            shutil.copyfile(pathlib.Path(directory, name), target / name)
            (target / name).chmod(pathlib.Path(directory, name).stat().st_mode & 0o777)
os.chdir('/work/source')
env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/work/home',
       'TMPDIR': '/tmp', 'CI': 'true', 'STAR_CONFIG_STRICT': '1', 'LANG': 'C.UTF-8',
       'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1'}
pathlib.Path(env['HOME']).mkdir()
if request.get('check'):
    pathlib.Path('/work/template').mkdir()
    for args in [['init', '--template=/work/template', '-q'], ['add', '--', '.']]:
        subprocess.run(['/usr/bin/git', *args], env=env, check=True, capture_output=True)
import tempfile, time
with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as input_file:
    input_file.write(request.get('stdin', '').encode())
    input_file.seek(0)
    result = subprocess.Popen(['/bin/sh', '-c', request['command']], env=env, close_fds=True,
                              stdin=input_file, stdout=output, stderr=subprocess.STDOUT)
    while result.poll() is None:
        if os.fstat(output.fileno()).st_size > 2097152:
            raise RuntimeError('workload output limit exceeded')
        time.sleep(0.05)
    output.seek(0)
    captured = output.read(2097153)
    if len(captured) > 2097152:
        raise RuntimeError('workload output limit exceeded')
changes = []
if request.get('check') and result.returncode == 0:
    for directory, dirs, files in os.walk('.'):
        if directory == '.': dirs[:] = [d for d in dirs if d != '.git']
        for name in dirs + files:
            item = pathlib.Path(directory, name)
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                raise RuntimeError('linked check output rejected')
        for name in files:
            item = pathlib.Path(directory, name)
            original = pathlib.Path('/input', item)
            if original.is_file() and item.read_bytes() != original.read_bytes():
                changes.append({'path': str(item), 'text': item.read_text()})
print(json.dumps({'exit_code': result.returncode,
                  'output': captured.decode(errors='replace'), 'changes': changes}))
'''


def protected_objects(source, policy):
    """Reserve literal protected objects, including currently absent paths."""
    objects = []
    for pattern in policy["protected_write_paths"]:
        directory = pattern.endswith("/**")
        name = pattern[:-3] if directory else pattern
        if (not name or name.startswith("/") or any(c in name for c in "*?[]\\")
                or any(p in ("", ".", "..") for p in name.split("/"))):
            raise Refused("protected mounts require literal paths or directory/** policies")
        target = source / name
        if directory:
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(0o755)
        elif not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"")
            target.chmod(0o644)
        objects.append(name)
    # A directory mount also protects all its children; avoid overlapping mounts.
    return sorted(p for p in set(objects) if not any(
        p.startswith(other + "/") for other in set(objects) if other != p))


def docker_args(image, name, source=None, protected=()):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise Refused("registered runtime image must be an immutable local sha256 ID")
    args = [DOCKER, "create", "--pull=never", "--name", name, "--runtime=runsc",
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--user=65534:65534",
            "--pids-limit=128", "--memory=1g", "--cpus=2", "--ipc=private",
            "--tmpfs", "/work:rw,nosuid,nodev,uid=65534,gid=65534,mode=0755,size=512m",
            "--tmpfs", "/work/source:rw,nosuid,nodev,uid=65534,gid=65534,mode=0755,size=512m",
            "--tmpfs", "/tmp:rw,nosuid,nodev,uid=65534,gid=65534,mode=0755,size=256m", "-i",
            "--entrypoint=/usr/bin/python3", image, "-I", "-c", BOOT]
    if source is not None:
        mounts = ["--mount", f"type=bind,source={source},target=/input,readonly,bind-propagation=rprivate"]
        parents = sorted({str(parent) for name in protected for parent in Path(name).parents if str(parent) != "."},
                         key=lambda name: (name.count("/"), name))
        for parent in parents:
            mounts += ["--tmpfs", f"/work/source/{parent}:rw,nosuid,nodev,uid=65534,gid=65534,mode=0755,size=256m"]
        for name in protected:
            mounts += ["--mount", f"type=bind,source={source}/{name},target=/work/source/{name},readonly,bind-propagation=rprivate"]
        args[2:2] = mounts
    return args


def execute(root, policy, image, command, stdin="", timeout=120, check=False):
    if not isinstance(command, str) or len(command) > 65536 or not isinstance(stdin, str):
        raise Refused("invalid execution request")
    if not isinstance(timeout, int) or not 1 <= timeout <= 600 or len(stdin) > MAX_OUTPUT:
        raise Refused("invalid request limits")
    archive, baseline = snapshot(root, policy)
    container_name = "agent-guard-" + uuid.uuid4().hex
    # Never inherit DOCKER_HOST, credential settings, import paths or provider keys.
    with tempfile.TemporaryDirectory(prefix="agent-guard-host-") as state:
        env = {"PATH": "/usr/bin:/bin", "HOME": state, "DOCKER_CONFIG": state}
        def control(args, **kw):
            result = subprocess.run(args, env=env, capture_output=True, timeout=30, **kw)
            if result.returncode:
                raise Refused("runtime control failed: " + result.stderr.decode(errors="replace")[:1000])
            return result
        source = Path(state) / "input"
        source.mkdir(mode=0o755)
        for filename, (contents, mode) in baseline.items():
            target = source / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents)
            target.chmod(mode)
        for directory, _, _ in os.walk(source):
            Path(directory).chmod(0o755)
        protected = protected_objects(source, policy)
        created = False
        try:
            control(docker_args(image, container_name, source, protected))
            created = True
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as input_file:
                input_file.write(json.dumps({"command": command, "stdin": stdin, "check": check,
                                             "protected": protected}).encode())
                input_file.seek(0)
                deadline = time.monotonic() + timeout
                proc = subprocess.Popen([DOCKER, "start", "-ai", container_name], env=env,
                                        stdin=input_file, stdout=output, stderr=output,
                                        close_fds=True)
                try:
                    while proc.poll() is None:
                        if time.monotonic() > deadline or os.fstat(output.fileno()).st_size > MAX_OUTPUT:
                            control([DOCKER, "kill", container_name])
                            raise Refused("execution time/output limit exceeded")
                        time.sleep(0.05)
                    output.seek(0)
                    data = output.read(MAX_OUTPUT + 1)
                    if len(data) > MAX_OUTPUT:
                        raise Refused("execution output limit exceeded")
                    if proc.returncode != 0:
                        raise Refused("runtime workload failed: " + data.decode(errors="replace")[:1000])
                    result = json.loads(data)
                    if not isinstance(result, dict) or not isinstance(result.get("exit_code"), int):
                        raise Refused("invalid workload result")
                    changes = result.get("changes", [])
                    if not isinstance(changes, list) or len(changes) > MAX_FILES:
                        raise Refused("invalid formatter result")
                    if changes and (not check or result["exit_code"] != 0):
                        raise Refused("unsuccessful checks cannot export changes")
                    prepared = []
                    for change in changes:
                        name, content = change["path"], change["text"]
                        parent, _ = file_parent(root, name, policy, writing=True)
                        os.close(parent)
                        if name not in baseline:
                            raise Refused("automatic checks may only format existing source files")
                        expected = hashlib.sha256(baseline[name][0]).hexdigest()
                        if read_file(root, name, policy)["sha256"] != expected:
                            raise Refused("source changed while checks ran")
                        prepared.append((name, content, expected))
                    output_text = result.get("output", "")
                    if not isinstance(output_text, str):
                        raise Refused("invalid workload output")
                    if prepared:
                        proposal = [{"path": path, "text": text, "expected_sha256": digest}
                                    for path, text, digest in prepared]
                        return 2, output_text + "\nFormatting changes require operator review and staging. Host files were not changed.\n" + json.dumps(proposal) + "\n"
                    return result["exit_code"], output_text
                finally:
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait()
        finally:
            if created:
                control([DOCKER, "rm", "-f", "--", container_name])


def registration(root):
    protected_install(__file__)
    protected_install(DOCKER)
    protected_install(REGISTRY)
    registered = json.loads(REGISTRY.read_text())
    canonical = str(Path(root).resolve(strict=True))
    item = registered[canonical]
    if not isinstance(item.get("policy"), dict):
        raise Refused("repository requires a reviewed host policy")
    for key in ("secret_paths", "quarantine_paths", "protected_write_paths"):
        if not isinstance(item["policy"].get(key), list):
            raise Refused("invalid registered policy")
    output_patterns()  # Missing/invalid trusted scanning prevents startup.
    return canonical, item


def file_parent(root, name, policy, writing=False):
    if (not isinstance(name, str) or not name or name.startswith("/")
            or any(p in ("", ".", "..") for p in name.split("/"))
            or "\x00" in name or excluded(name, policy)):
        raise Refused("file path is outside the permitted source tree")
    if writing and matches(name, policy["protected_write_paths"]):
        raise Refused("protected file requires a separately reviewed human change")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in name.split("/")[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, name.split("/")[-1]
    except BaseException:
        os.close(fd)
        raise


def read_file(root, name, policy):
    parent, leaf = file_parent(root, name, policy)
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
                raise Refused("not a bounded independent regular file")
            with os.fdopen(os.dup(fd), "rb") as source:
                data = source.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise Refused("file size limit exceeded")
            return {"text": data.decode("utf-8"), "sha256": hashlib.sha256(data).hexdigest()}
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def write_file(root, name, text, expected_sha256, policy):
    """Replace a file in the broker-private serialized namespace only.

    Never call on a live checkout: concurrent ancestor renames invalidate path
    policy even when directory descriptors and O_NOFOLLOW are used.
    """
    if not isinstance(text, str) or len(text.encode()) > MAX_FILE:
        raise Refused("invalid file contents")
    parent, leaf = file_parent(root, name, policy, writing=True)
    temporary = ".agent-guard-write-" + uuid.uuid4().hex
    try:
        try:
            info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            info = None
        if info is None:
            if expected_sha256 is not None:
                raise Refused("source changed: target no longer exists")
            mode = 0o644
        else:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise Refused("linked or nonregular write target")
            if expected_sha256 != read_file(root, name, policy)["sha256"]:
                raise Refused("source changed: read current contents before writing")
            mode = 0o755 if info.st_mode & 0o111 else 0o644
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        with os.fdopen(fd, "wb") as target:
            target.write(text.encode())
            target.flush()
            os.fsync(target.fileno())
        if info is None:
            # Atomic create-if-absent: do not overwrite a concurrent new file.
            os.link(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        else:
            current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if (current.st_ino, current.st_mtime_ns, current.st_ctime_ns) != (
                    info.st_ino, info.st_mtime_ns, info.st_ctime_ns):
                raise Refused("source changed before replacement")
            os.replace(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent)
        return {"sha256": hashlib.sha256(text.encode()).hexdigest()}
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


TOOLS = [
    {"name": "export_changes", "description": "Return proposed source changes for the trusted operator/publication path; never apply to the host checkout.",
     "inputSchema": {"type": "object", "properties": {}, "required": [], "additionalProperties": False}},
    {"name": "execute", "description": "Run a command in a disposable, networkless source copy. No host effects.",
     "inputSchema": {"type": "object", "properties": {"command": {"type": "string"},
                      "stdin": {"type": "string"}, "timeout": {"type": "integer", "minimum": 1, "maximum": 600}},
                     "required": ["command"], "additionalProperties": False}},
    {"name": "read_file", "description": "Read an authorized regular source file without following links.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                     "required": ["path"], "additionalProperties": False}},
    {"name": "write_file", "description": "Replace an authorized regular file using its last-read digest; null creates a new file.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "text": {"type": "string"},
                      "expected_sha256": {"type": ["string", "null"]}},
                     "required": ["path", "text", "expected_sha256"], "additionalProperties": False}},
]


def serve(root, config):
    """All editing occurs in a private controller namespace, never the live checkout.

    No untrusted process can see or rename this namespace. Only the serialized
    broker writes it; execute() mounts a different read-only snapshot.
    """
    _, baseline = snapshot(root, config["policy"])
    with tempfile.TemporaryDirectory(prefix="agent-guard-session-") as session:
        for name, (data, mode) in baseline.items():
            target = Path(session) / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(mode)
        serve_session(session, config, baseline)


def serve_session(root, config, baseline):
    """MCP stdio endpoint; only serve() supplies the private serialized namespace."""
    sizes = {name: len(data) for name, (data, _) in baseline.items()}
    total = sum(sizes.values())
    while True:
        line = sys.stdin.readline(MAX_OUTPUT + 1)
        if not line:
            break
        if len(line) > MAX_OUTPUT:
            raise Refused("protocol message too large")
        request = json.loads(line)
        if "id" not in request:
            continue
        response = {"jsonrpc": "2.0", "id": request["id"]}
        method = request.get("method")
        try:
            if method == "initialize":
                response["result"] = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                                      "serverInfo": {"name": "agent_guard", "version": "3.0.0"}}
            elif method == "ping":
                response["result"] = {}
            elif method == "tools/list":
                response["result"] = {"tools": TOOLS}
            elif method == "tools/call":
                params = request["params"]
                args = params.get("arguments", {})
                name = params["name"]
                declaration = next((t for t in TOOLS if t["name"] == name), None)
                if declaration is None or not isinstance(args, dict):
                    raise Refused("unknown tool or invalid arguments")
                schema = declaration["inputSchema"]
                if set(args) - set(schema["properties"]) or set(schema["required"]) - set(args):
                    raise Refused("unexpected or missing arguments")
                if name == "execute":
                    code, output = execute(root, config["policy"], config["image"], **args)
                    value = {"exit_code": code, "output": output}
                elif name == "read_file":
                    value = read_file(root, args["path"], config["policy"])
                elif name == "export_changes":
                    _, current = snapshot(root, config["policy"])
                    value = {"files": [{"path": path, "text": data.decode("utf-8"),
                               "expected_sha256": hashlib.sha256(baseline[path][0]).hexdigest() if path in baseline else None}
                              for path, (data, _) in current.items()
                              if path not in baseline or data != baseline[path][0]]}
                else:
                    name, contents = args["path"], args["text"]
                    if not isinstance(name, str) or not isinstance(contents, str):
                        raise Refused("invalid file contents or path")
                    size = len(contents.encode())
                    # Include the old file while its atomic replacement is staged.
                    if total + size > MAX_TOTAL or (name not in sizes and len(sizes) >= MAX_FILES):
                        raise Refused("session storage quota exceeded")
                    value = write_file(root, name, contents, args["expected_sha256"], config["policy"])
                    total += size - sizes.get(name, 0)
                    sizes[name] = size
                response["result"] = {"content": [{"type": "text", "text": json.dumps(checked_output(value))}]}
            else:
                response["error"] = {"code": -32601, "message": "unsupported method"}
        except (Refused, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
            response["result"] = {"isError": True, "content": [{"type": "text", "text": "Broker operation refused; trusted validation did not pass"}]}
        print(json.dumps(response), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["execute", "check", "serve", "pretool", "preflight"])
    parser.add_argument("argument", nargs="?")
    args = parser.parse_args()
    try:
        root, config = registration(os.getcwd())
        if args.operation == "preflight":
            code, output = execute(root, config["policy"], config["image"],
                                   "/usr/bin/python3 -I -c 'import os; assert os.getuid() == 65534'", timeout=30)
            sys.stdout.write(checked_output(output))
            return code
        if args.operation == "serve":
            serve(root, config)
            return 0
        if args.operation == "pretool":
            event = json.load(sys.stdin)
            tool = event.get("tool_name") or event.get("toolName")
            if tool not in {"mcp__agent_guard__" + t["name"] for t in TOOLS}:
                raise Refused("raw host tools are disabled; use the registered agent_guard broker")
            return 0
        if args.operation == "check":
            # Explicit declaration only: no inferred npx/eslint/tool probing.
            checks = config.get("checks", {})
            if args.argument not in checks:
                raise Refused("required check phase is not registered: " + args.argument)
            command = checks[args.argument]
        else:
            command = args.argument
        code, output = execute(root, config["policy"], config["image"], command,
                               stdin=sys.stdin.read(MAX_OUTPUT + 1), timeout=600, check=args.operation == "check")
        sys.stdout.write(checked_output(output))
        return code
    except (Refused, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        sys.stderr.write("agent-guard: isolated execution refused; trusted validation did not pass\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())

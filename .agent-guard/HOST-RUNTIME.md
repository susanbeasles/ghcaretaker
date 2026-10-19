# Isolated agent execution (3.0 migration)

The checkout is not a trusted location for enforcement code. Version 3 refuses
unconfined shell execution and dispatches automatic checks to the fixed host
runner `/opt/agent-guard/bin/agent-guard`. Missing installation is a failure;
there is no fallback to repository scripts on the host.

## Required installation boundary

An administrator must review and install the release's `runtime.py` as
`/opt/agent-guard/lib/runtime.py`, `host/bin/agent-guard` as
`/opt/agent-guard/bin/agent-guard`, and the two `host/git-hooks/` scripts in
`/opt/agent-guard/git-hooks/`. Executables require mode 0755. All installed files,
the registry and every ancestor must be owned by root, not group/world writable,
and not symbolic links. The runtime verifies its own location, the registry and
`/usr/bin/docker` before processing requests. The host must also provide its
trusted `/usr/bin/python3` and `/bin/sh` interpreters. Installation and client
configuration are separate operator actions; pack distribution does not do them.

Use an existing Docker Engine configured with `runsc`. Select a reviewed, local
image by immutable `sha256:<64 hex>` ID, containing `/usr/bin/python3`, `/bin/sh`,
`/usr/bin/git` and the repository's required offline toolchain/dependencies.
There is no automatic pull, runtime downgrade, package download or host fallback.
The image is trusted executable input, including all Python startup modules and
shared libraries. Prepare it separately; do not build it from an unreviewed repo.

The host registry `/etc/agent-guard/repositories.json` maps canonical repository
roots to `image`, a reviewed copy of that repository's `policy`, and `checks`.
For example, the structure is:

```json
{
  "/absolute/registered/repository": {
    "image": "sha256:<approved-local-image-id>",
    "policy": {
      "secret_paths": ["**/.env", "**/.env.*", "**/*.key"],
      "quarantine_paths": ["vendor/**", "node_modules/**"],
      "protected_write_paths": [".agent-guard/**", ".guard/**", ".claude/**", ".codex/**", ".github/**", "AGENTS.md", "CLAUDE.md"]
    },
    "checks": {
      "stop": "<exact required offline CI checks>",
      "post-edit": "<declared required checks receiving event JSON on stdin>",
      "pre-commit": "<declared required commit checks>",
      "pre-push": "<declared required push checks>"
    }
  }
}
```

This example is deliberately not a runnable registration. Preserve every existing
repository-specific policy restriction when registering it. No checkout-local
policy or environment variable can expand the host registry. Check commands are
explicit declarations, not inferred from npx or a package.json. Missing required
tools/commands fail. For ghcaretaker, register its policy, test/build, guard and
gitleaks requirements; do not invent an ESLint requirement. Do not use a legacy
check script that silently skips required tools as the declaration.

## Client integration prerequisite

The supported execution API is the MCP stdio service started by the trusted client
with `/opt/agent-guard/bin/agent-guard serve`, cwd set to the registered root and
server name `agent_guard`. It offers only `execute`, `read_file`, `write_file`, `export_changes`.
The client must disable native host shell/file tools and project-local hook/MCP
autoload **before opening an untrusted revision**, using operator-managed client
configuration. It must not permit the checkout to replace the registered server.
Where the client supports a trusted pre-tool hook, use the installed `pretool`
entrypoint with a catch-all matcher; it denies all raw host tools. Configure the
installed `check` entrypoints for post-edit and Stop events.

The tracked configs provide the dispatch commands but cannot enforce their own
trusted loading. A client that cannot disable project hook/config execution or
raw tools is unsupported. Do not call it protected because a wrapper exists or a
pre-hook unit test passes. Production Codex/Claude/Copilot adapter qualification
remains a required installation acceptance step. No source patch alone changes
already-installed clients or host Git hook configuration.

## Execution and file semantics

Arbitrary interpreters and nested shells execute in a private runsc container,
non-root, network disabled, read-only root, all capabilities dropped, no privilege
gain, bounded PID/memory/CPU/time/output. Only a newly created sanitized snapshot
directory is mounted read-only. The original checkout, .git, home, credentials,
Docker/SSH sockets and host environment are not mounted or forwarded. Work and
temporary directories are disposable tmpfs; local test servers can use loopback.
Protected objects in the working copy are separate read-only mounts, including
reserved absent paths. Parent directories needed for those mounts are independent
tmpfs mounts. Protected mount policies support literal paths and directory/**;
unrepresentable glob policies fail closed instead of being ignored.
No-network applies to project execution, not the separately trusted model client.

Snapshot traversal uses directory descriptors and no-follow opens, rejects links,
hardlinks and special files, and omits secret/quarantined paths. The worker cannot
select images, runtime, mounts or environment. `execute` changes are disposable.
Source edits use `read_file` plus digest-checked `write_file` in a private
controller-owned session copy, with no-follow traversal and protected-path
enforcement. No untrusted process can rename that host namespace: project code
runs only against a separate container snapshot. `export_changes` returns
structured proposals and original digests for the existing trusted operator
review/publication path. It never applies to the live checkout. This prevents
branch switches and concurrent checkout renames from redirecting broker writes.
Parents must already exist. New directories, deletion and renaming require
separately reviewed tooling.

Checks receive a synthetic staged Git index, never host Git configuration or
credentials. Successful checks may return formatting proposals for existing ordinary
files. The controller verifies policy and original digests before presenting them.
Any such changes return exit 2 and require operator review/application/restaging
before the gate can pass. No check modifies the live host checkout. Host Git is never invoked to stage arbitrary checkout filters. Protected
changes, links, stale source and failed checks cannot export formatting edits.

## Acceptance evidence

`tests/test_runtime.py` exercises broker/protocol/path rules. The non-skipping
`tests/test_runtime_integration.py` requires `GUARD_TEST_IMAGE` and optionally
`GUARD_TEST_DOCKER` (test harness only). It runs Python, Node and nested shell,
denied network/mount/secret access, normal writes and loopback services, formatter
export and failure-without-fallback against real runsc. These are runtime/MCP
protocol tests, not claims of qualification for a vendor's complete client.

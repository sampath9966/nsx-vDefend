#!/usr/bin/env python3
"""Prove that `pip install nsxctl` gives someone a working command.

Builds the distributions, installs the wheel into a throwaway virtualenv, and
drives the *installed console script* against a fake NSX as a subprocess.
Nothing here imports the package: what is exercised is exactly what a user
gets from PyPI, launcher and all.

The virtualenv is deliberately bare -- no `requests` -- so this also covers
the stdlib urllib transport, which is the one that runs on a jumpbox with no
package access.

    python tools/verify_install.py            # build, install, drive
    python tools/verify_install.py --wheel W  # drive an already-built wheel

Exit status is 0 only if every check passed.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from fake_nsx import FakeNsx  # noqa: E402  (needs the path set above)


class Checks:
    """Runs commands, records what failed, and prints as it goes."""

    def __init__(self, binary, inventory, cwd, env):
        self.binary = binary
        self.inventory = inventory
        self.cwd = cwd
        self.env = env
        self.failures = []
        self.passed = 0

    def run(self, *args, expect=0, inventory=True, label=None):
        cmd = [self.binary]
        if inventory:
            cmd += ["--inventory", self.inventory, "--non-interactive"]
        cmd += list(args)
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=self.cwd, env=self.env)
        name = label or " ".join(args) or "(no args)"
        if result.returncode != expect:
            self.fail("{}: exit {} (wanted {})\nSTDOUT:\n{}\nSTDERR:\n{}".format(
                name, result.returncode, expect,
                result.stdout[-1500:], result.stderr[-1500:]), name)
        else:
            self.ok(name)
        return result

    def ok(self, name):
        self.passed += 1
        print("  ok    {}".format(name))

    def fail(self, detail, name=None):
        self.failures.append(detail)
        print("  FAIL  {}".format(name or detail.splitlines()[0]))

    def expect_in(self, needle, haystack, name):
        if needle in haystack:
            self.ok(name)
        else:
            self.fail("{}: expected {!r} in output".format(name, needle), name)


def build_wheel(outdir):
    """Build sdist and wheel the way a release does, and return the wheel."""
    print("Building distributions...")
    subprocess.run([sys.executable, "-m", "build", "--outdir", outdir],
                   cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    wheels = [f for f in os.listdir(outdir) if f.endswith(".whl")]
    if len(wheels) != 1:
        raise SystemExit("expected exactly one wheel, found {}".format(wheels))
    return os.path.join(outdir, wheels[0])


def install(wheel, venv_dir):
    """A clean virtualenv with only the wheel in it."""
    print("Installing {} into a clean virtualenv...".format(
        os.path.basename(wheel)))
    subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True)
    pip = os.path.join(venv_dir, "bin", "pip")
    subprocess.run([pip, "install", "--quiet", wheel], check=True)
    return os.path.join(venv_dir, "bin", "nsxctl")


def drive(binary, tmp):
    """Every surface a user touches, against a GM and two Local Managers."""
    gm = FakeNsx(role="gm", name="gm").start()
    lm1 = FakeNsx(role="lm", name="lm-london").start()
    lm2 = FakeNsx(role="lm", name="lm-frankfurt").start()
    fakes = [gm, lm1, lm2]

    os.makedirs(tmp, exist_ok=True)
    inventory = os.path.join(tmp, "inventory.json")
    with open(inventory, "w", encoding="utf-8") as f:
        json.dump({"managers": [x.entry() for x in fakes]}, f)

    env = dict(os.environ)
    env.update({"HOME": tmp, "USERPROFILE": tmp,
                "FAKE_USER": "svc-nsx", "FAKE_PASS": "secret",
                "NSX_TOOLKIT_CREDENTIALS_FILE": os.path.join(tmp, "creds.env"),
                "NO_COLOR": "1"})

    c = Checks(binary, inventory, tmp, env)
    try:
        print("\nThe command itself")
        version = c.run("--version", inventory=False, label="nsxctl --version")
        c.expect_in("NSX Toolkit", version.stdout, "version string")
        c.run("--help", inventory=False, label="nsxctl --help")

        # An estate to look at.
        gm.state.add_group("gg1")
        gm.state.add_policy("gpol")
        for fake in (lm1, lm2):
            fake.state.add_group("lg1")
            fake.state.add_policy("lpol")
        lm1.state.add_vm("lon-web1", tags=[("env", "prod"), ("tier", "web")])
        lm2.state.add_vm("fra-web1", tags=[("env", "prod")])

        print("\nReading the estate")
        status = c.run("status")
        for manager in ("gm", "lm-london", "lm-frankfurt"):
            c.expect_in(manager, status.stdout,
                        "status reaches {}".format(manager))
        c.run("doctor")
        c.run("compliance", "--json")
        c.run("group", "list")
        c.run("rule", "list")
        c.run("policy", "list")
        c.run("service", "list")
        c.run("rule", "hygiene")

        print("\nSnapshot and drift")
        c.run("snapshot", "save", "baseline")
        c.run("drift")
        c.run("snapshot", "list")

        print("\nTracing")
        # Nothing matches tcp/3306 yet. There is no verdict to give, and the
        # command says so and exits 1 rather than inventing one.
        no_match = c.run("trace", "lon-web1", "fra-web1", "--port", "3306",
                         "--static", expect=1,
                         label="trace with no matching rule exits 1")
        c.expect_in("NO MATCH", no_match.stdout, "trace says NO MATCH")
        lm1.state.add_rule("lpol", "allow-mysql", action="ALLOW")
        c.run("trace", "lon-web1", "fra-web1", "--port", "3306", "--static",
              label="trace with a matching rule")

        print("\nAuthoring")
        # Without --enable-writes this must plan and write nothing.
        c.run("group", "create", "g-e2e", "--criteria", "tag:env=prod",
              label="group create (dry run)")
        listing = c.run("group", "list", label="group list after dry run")
        if "g-e2e" in listing.stdout:
            c.fail("the dry run created the group; it must plan only",
                   "dry run wrote nothing")
        else:
            c.ok("dry run wrote nothing")

        c.run("group", "create", "g-e2e", "--criteria", "tag:env=prod",
              "--enable-writes", "--yes", label="group create (committed)")
        listing = c.run("group", "list", label="group list after write")
        c.expect_in("g-e2e", listing.stdout, "the group was created")
        audit = c.run("audit", "list")
        c.expect_in("g-e2e", audit.stdout, "the write is in the audit log")

        print("\nScheduled operation")
        sinks = {"junit.xml": "--out-junit", "findings.sarif": "--out-sarif",
                 "metrics.prom": "--out-metrics"}
        args = []
        for name, flag in sinks.items():
            args += [flag, os.path.join(tmp, name)]
        c.run(*(args + ["rule", "hygiene"]), label="hygiene with all sinks")
        for name in sinks:
            path = os.path.join(tmp, name)
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                c.ok("{} written ({} bytes)".format(name,
                                                    os.path.getsize(path)))
            else:
                c.fail("{} was not written".format(name), name)

        print("\nShell integration")
        # Completion must never need the network or the inventory.
        c.run("completion", "bash", inventory=False, label="completion bash")
    finally:
        for fake in fakes:
            fake.stop()
    return c


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", help="use this wheel instead of building")
    parser.add_argument("--keep", action="store_true",
                        help="keep the virtualenv and working directory")
    args = parser.parse_args()

    workdir = tempfile.mkdtemp(prefix="nsxctl-verify-")
    try:
        wheel = args.wheel or build_wheel(os.path.join(workdir, "dist"))
        binary = install(wheel, os.path.join(workdir, "venv"))
        if not os.path.isfile(binary):
            raise SystemExit(
                "the wheel installed but put no nsxctl on PATH: {}".format(
                    binary))
        checks = drive(binary, os.path.join(workdir, "run"))
    finally:
        if args.keep:
            print("\nkept: {}".format(workdir))
        else:
            shutil.rmtree(workdir, ignore_errors=True)

    print("\n" + "=" * 68)
    if checks.failures:
        print("{} FAILED, {} passed\n".format(len(checks.failures),
                                              checks.passed))
        for failure in checks.failures:
            print(failure)
            print("-" * 40)
        return 1
    print("{} checks passed against the installed console script".format(
        checks.passed))
    return 0


if __name__ == "__main__":
    sys.exit(main())

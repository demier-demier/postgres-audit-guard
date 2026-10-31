"""Create an isolated socket-only PostgreSQL 15+ lab and capture real jsonlog records.

Only original synthetic banking data is used. No existing cluster is contacted.
The newly created cluster is stopped in finally; files remain for inspection.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--bindir", type=Path)
    args = parser.parse_args()
    bindir = args.bindir or Path(
        subprocess.check_output(["pg_config", "--bindir"], text=True).strip()
    )
    work = args.work_dir.resolve()
    if len(os.fsencode(str(work / "socket" / ".s.PGSQL.55431"))) > 100:
        raise ValueError(
            "Use a shorter --work-dir, such as /tmp/postgres-audit-lab: Unix socket path is too long"
        )
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    socket = work / "socket"
    socket.mkdir(mode=0o700)
    cluster = work / "cluster"
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("PG")}
    env.update(PGAPPNAME="postgres-audit-lab", LC_ALL="C")

    def run(command, **kwargs):
        return subprocess.run(
            command, env=env, capture_output=True, text=True, timeout=60, **kwargs
        )

    init = run(
        [str(bindir / "initdb"), "-D", str(cluster), "-U", "lab_admin", "-A", "trust"],
        check=True,
    )
    (work / "init.log").write_text(init.stdout + init.stderr)
    # Unix socket permissions plus 0700 ancestor restrict trust authentication to this user.
    conf = (
        "\n".join(
            [
                "listen_addresses = ''",
                "port = 55431",
                "unix_socket_permissions = 0700",
                "unix_socket_directories = '" + str(socket).replace("'", "''") + "'",
                "logging_collector = on",
                "log_destination = 'jsonlog'",
                "log_directory = 'log'",
                "log_filename = 'bank-lab'",
                "log_statement = 'all'",
                "log_min_messages = 'warning'",
                "log_timezone = 'UTC'",
                "log_error_verbosity = 'terse'",
                "log_connections = off",
                "log_disconnections = off",
            ]
        )
        + "\n"
    )
    with (cluster / "postgresql.conf").open("a") as f:
        f.write(conf)
    attempted_start = False
    observed = []
    try:
        attempted_start = True
        run(
            [
                str(bindir / "pg_ctl"),
                "-D",
                str(cluster),
                "-l",
                str(work / "startup.log"),
                "-w",
                "start",
            ],
            check=True,
        )
        base = [
            str(bindir / "psql"),
            "-h",
            str(socket),
            "-p",
            "55431",
            "-U",
            "lab_admin",
            "-d",
            "postgres",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
        ]
        run(base + ["-c", "CREATE DATABASE bank_lab"], check=True)
        base[base.index("postgres")] = "bank_lab"
        run(
            base
            + [
                "-c",
                "CREATE ROLE lab_reader LOGIN; CREATE TABLE public.bank_accounts(id integer, account_ref text, balance_minor bigint); INSERT INTO public.bank_accounts VALUES(1,'SYNTHETIC-001',12000),(2,'SYNTHETIC-002',8000); GRANT SELECT ON public.bank_accounts TO lab_reader;",
            ],
            check=True,
        )
        cases = [
            ("control-benign", "SELECT 1", 0),
            (
                "control-literal",
                "SELECT 'ALTER ROLE lab_reader SUPERUSER; COPY bank_accounts TO STDOUT'",
                0,
            ),
            ("case-role-attempt", "ALTER ROLE lab_reader SUPERUSER", 1),
            (
                "case-sensitive-export",
                "COPY public.bank_accounts TO STDOUT WITH CSV",
                0,
            ),
            ("case-disable-logging", "SET log_statement = 'none'", 1),
            ("case-permission-denied", "DELETE FROM public.bank_accounts", 1),
        ]
        reader = list(base)
        reader[reader.index("lab_admin")] = "lab_reader"
        for app, sql, expected in cases:
            env["PGAPPNAME"] = app
            p = run(reader + ["-c", sql])
            if (p.returncode != 0) != (expected != 0):
                raise RuntimeError(f"Unexpected outcome in {app}: {p.stderr}")
            observed.append(
                {
                    "case": app,
                    "sql": sql,
                    "exit_code": p.returncode,
                    "database_outcome": "succeeded"
                    if p.returncode == 0
                    else "rejected",
                }
            )
        env["PGAPPNAME"] = "postgres-audit-lab"
        run(base + ["-c", "SELECT pg_rotate_logfile()"], check=True)
        time.sleep(0.3)
    finally:
        if attempted_start:
            status = run([str(bindir / "pg_ctl"), "-D", str(cluster), "status"])
            if status.returncode == 0:
                run(
                    [
                        str(bindir / "pg_ctl"),
                        "-D",
                        str(cluster),
                        "-m",
                        "fast",
                        "-w",
                        "stop",
                    ],
                    check=True,
                )
            elif status.returncode != 3:
                raise RuntimeError(
                    "Cannot confirm isolated cluster is stopped; inspect its saved work directory"
                )
    # Preserve only case logs in the shareable fixture. No startup paths, OS user or setup SQL.
    output = work / "postgres-cases.jsonl"
    count = 0
    with output.open("wb") as dst:
        for path in sorted((cluster / "log").glob("*.json")):
            for line in path.read_bytes().splitlines(keepends=True):
                obj = json.loads(line)
                if obj.get("application_name", "").startswith(("case-", "control-")):
                    dst.write(line)
                    count += 1
    if count < len(cases):
        raise RuntimeError("Missing PostgreSQL case logs")
    report = {
        "schema": "postgres-audit-postgres-lab/v1",
        "postgres_version": run(
            [str(bindir / "postgres"), "--version"], check=True
        ).stdout.strip(),
        "scope": "Actual socket-only local PostgreSQL; original synthetic data; not a bank system.",
        "network_listener": False,
        "cluster_stopped": True,
        "records": count,
        "cases": observed,
    }
    (work / "lab-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

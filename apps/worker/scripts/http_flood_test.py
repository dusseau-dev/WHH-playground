#!/usr/bin/env python3
"""Authorized, single-host HTTP GET load and capacity assessment.

This program is for educational and authorized use only. Run it solely against
systems you own or have explicit written permission to test. It deliberately
uses the host operating system's normal network path: there is no source-address
spoofing, proxy rotation, distributed execution, amplification, or redirect
following.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import signal
import ssl
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


LEGAL_DISCLAIMER = """
LEGAL NOTICE:
  This tool generates HTTP load and must only be used against systems you own
  or have explicit written permission to test. Unauthorized load testing may be
  illegal and may disrupt services. You are responsible for choosing safe test
  parameters and coordinating with affected operators.
""".strip()

DEFAULT_USER_AGENT = "shannon-http-load/1.0 authorized-single-host-capacity-test"
RESERVED_HEADERS = {"host", "connection", "content-length", "transfer-encoding", "user-agent"}
SENSITIVE_QUERY_KEY = re.compile(
    r"(?:api[-_]?key|auth|bearer|cookie|credential|email|key|password|secret|session|token)",
    re.IGNORECASE,
)
REDACTED = "[REDACTED]"
MAX_CONCURRENCY = 1_000
MAX_REQUESTS_PER_SECOND = 10_000
MAX_DURATION_SECONDS = 3_600


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp for the machine-readable result."""

    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Target:
    """Validated URL components used to open a direct socket and build a GET."""

    url: str
    scheme: str
    host: str
    host_header: str
    port: int
    path_and_query: str
    tls_server_name: str | None


@dataclass(frozen=True)
class LoadConfig:
    """Normalized runtime options shared by the producer and request workers."""

    target: Target
    concurrency: int
    rate: float
    duration: float
    timeout: float
    read_limit: int
    progress_interval: float
    headers: tuple[tuple[str, str], ...]
    user_agents: tuple[str, ...]
    ssl_context: ssl.SSLContext | None


@dataclass
class Stats:
    """Concurrency-safe aggregate metrics; individual request errors are not logged."""

    started_at: float = field(default_factory=time.perf_counter)
    sent: int = 0
    completed: int = 0
    success: int = 0
    failure: int = 0
    errors: int = 0
    bytes_read: int = 0
    total_latency_ms: float = 0.0
    min_latency_ms: float | None = None
    max_latency_ms: float | None = None
    status_counts: Counter[int] = field(default_factory=Counter)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def record_sent(self) -> None:
        async with self.lock:
            self.sent += 1

    async def record_response(self, status_code: int, latency_ms: float, bytes_read: int) -> None:
        async with self.lock:
            self.completed += 1
            self.bytes_read += bytes_read
            self.total_latency_ms += latency_ms
            self.min_latency_ms = latency_ms if self.min_latency_ms is None else min(self.min_latency_ms, latency_ms)
            self.max_latency_ms = latency_ms if self.max_latency_ms is None else max(self.max_latency_ms, latency_ms)
            self.status_counts[status_code] += 1
            if 200 <= status_code < 400:
                self.success += 1
            else:
                self.failure += 1

    async def record_error(self) -> None:
        async with self.lock:
            self.errors += 1

    async def snapshot(self) -> dict[str, object]:
        async with self.lock:
            average = self.total_latency_ms / self.completed if self.completed else 0.0
            return {
                "elapsed": time.perf_counter() - self.started_at,
                "sent": self.sent,
                "completed": self.completed,
                "success": self.success,
                "failure": self.failure,
                "errors": self.errors,
                "bytes_read": self.bytes_read,
                "avg_latency_ms": average,
                "min_latency_ms": self.min_latency_ms,
                "max_latency_ms": self.max_latency_ms,
                "status_counts": dict(sorted(self.status_counts.items())),
            }


def positive_int(value: str) -> int:
    """Validate a positive integer command-line value."""

    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def positive_float(value: str) -> float:
    """Validate a finite, positive numeric command-line value."""

    parsed = float(value)
    if not parsed > 0 or parsed == float("inf"):
        raise argparse.ArgumentTypeError("must be a finite value greater than zero")
    return parsed


def bounded_positive_int(label: str, maximum: int):
    """Build an argparse integer parser with a hard emergency ceiling."""

    def parse(value: str) -> int:
        parsed = positive_int(value)
        if parsed > maximum:
            raise argparse.ArgumentTypeError(f"{label} must not exceed {maximum:,}")
        return parsed

    return parse


def bounded_positive_float(label: str, maximum: float):
    """Build an argparse numeric parser with a hard emergency ceiling."""

    def parse(value: str) -> float:
        parsed = positive_float(value)
        if parsed > maximum:
            raise argparse.ArgumentTypeError(f"{label} must not exceed {maximum:,.0f}")
        return parsed

    return parse


def parse_target(raw_url: str) -> Target:
    """Validate an HTTP(S) target without embedded credentials."""

    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise argparse.ArgumentTypeError("target URL must use http:// or https://")
    if not parsed.hostname:
        raise argparse.ArgumentTypeError("target URL must include a hostname")
    if parsed.username or parsed.password:
        raise argparse.ArgumentTypeError("target URL must not include embedded credentials")

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise argparse.ArgumentTypeError("target URL contains an invalid port") from error
    path_and_query = parsed.path or "/"
    if parsed.query:
        path_and_query = f"{path_and_query}?{parsed.query}"

    default_port = 443 if parsed.scheme == "https" else 80
    host_for_header = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    host_header = host_for_header if port == default_port else f"{host_for_header}:{port}"
    return Target(
        url=raw_url,
        scheme=parsed.scheme,
        host=parsed.hostname,
        host_header=host_header,
        port=port,
        path_and_query=path_and_query,
        tls_server_name=parsed.hostname if parsed.scheme == "https" else None,
    )


def sanitize_target(raw_url: str) -> str:
    """Redact sensitive query values before writing the target to an artifact."""

    parsed = urlsplit(raw_url)
    sanitized_query = urlencode(
        [(key, REDACTED if SENSITIVE_QUERY_KEY.search(key) else value) for key, value in parse_qsl(parsed.query)],
        doseq=True,
    )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", sanitized_query, ""))


def parse_header(value: str) -> tuple[str, str]:
    """Parse one ``Name: value`` header while preserving controlled headers."""

    if ":" not in value:
        raise argparse.ArgumentTypeError('headers must use the form "Name: value"')
    name, header_value = (part.strip() for part in value.split(":", 1))
    if not name or not header_value:
        raise argparse.ArgumentTypeError("header name and value must both be non-empty")
    if name.lower() in RESERVED_HEADERS:
        raise argparse.ArgumentTypeError(f"{name!r} is managed by this tool")
    if "\r" in name or "\n" in name or "\r" in header_value or "\n" in header_value:
        raise argparse.ArgumentTypeError("headers must not contain newline characters")
    return name, header_value


def load_user_agents(values: Iterable[str], filename: str | None) -> tuple[str, ...]:
    """Build the rotation list from repeated flags and an optional line file."""

    user_agents = [value.strip() for value in values if value.strip()]
    if filename:
        with open(filename, "r", encoding="utf-8") as handle:
            for line in handle:
                candidate = line.strip()
                if candidate and not candidate.startswith("#"):
                    user_agents.append(candidate)
    return tuple(user_agents or [DEFAULT_USER_AGENT])


def make_ssl_context(insecure_tls: bool) -> ssl.SSLContext:
    """Create a normal verified TLS context unless explicitly disabled."""

    context = ssl.create_default_context()
    if insecure_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def build_request(config: LoadConfig, sequence: int) -> bytes:
    """Construct one bounded, connection-closing HTTP/1.1 GET request."""

    user_agent = config.user_agents[sequence % len(config.user_agents)]
    lines = [
        f"GET {config.target.path_and_query} HTTP/1.1",
        f"Host: {config.target.host_header}",
        f"User-Agent: {user_agent}",
        "Accept: */*",
        "Connection: close",
    ]
    lines.extend(f"{name}: {value}" for name, value in config.headers)
    return ("\r\n".join([*lines, "", ""])).encode("utf-8")


def parse_status_code(header_block: bytes) -> int:
    """Extract the status code from the first response line."""

    first_line = header_block.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    parts = first_line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ValueError("invalid HTTP response status line")
    return int(parts[1])


async def read_response(reader: asyncio.StreamReader, timeout: float, read_limit: int) -> tuple[int, int]:
    """Read headers and at most ``read_limit`` bytes before closing the socket."""

    header_block = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
    status_code = parse_status_code(header_block)
    total_read = len(header_block)
    remaining = max(0, read_limit - total_read)
    while remaining > 0:
        chunk = await asyncio.wait_for(reader.read(min(65_536, remaining)), timeout=timeout)
        if not chunk:
            break
        total_read += len(chunk)
        remaining -= len(chunk)
    return status_code, total_read


async def send_one_request(config: LoadConfig, sequence: int, stats: Stats) -> None:
    """Open one direct connection, issue one GET, and aggregate its outcome."""

    await stats.record_sent()
    started = time.perf_counter()
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                config.target.host,
                config.target.port,
                ssl=config.ssl_context,
                server_hostname=config.target.tls_server_name if config.ssl_context else None,
                limit=max(65_536, config.read_limit),
            ),
            timeout=config.timeout,
        )
        writer.write(build_request(config, sequence))
        await asyncio.wait_for(writer.drain(), timeout=config.timeout)
        status_code, bytes_read = await read_response(reader, config.timeout, config.read_limit)
        await stats.record_response(status_code, (time.perf_counter() - started) * 1000, bytes_read)
    except Exception:
        # Per-request details can contain sensitive network context and can
        # overwhelm logs. The bounded aggregate error count is sufficient.
        await stats.record_error()
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def worker(queue: asyncio.Queue[int | None], config: LoadConfig, stats: Stats) -> None:
    """Consume scheduled sequence numbers with fixed concurrency."""

    while True:
        sequence = await queue.get()
        try:
            if sequence is None:
                return
            await send_one_request(config, sequence, stats)
        finally:
            queue.task_done()


async def producer(queue: asyncio.Queue[int | None], config: LoadConfig, stop_event: asyncio.Event) -> None:
    """Schedule starts at an absolute rate without creating an unbounded backlog."""

    loop = asyncio.get_running_loop()
    started = loop.time()
    end = started + config.duration
    sequence = 0
    while loop.time() < end and not stop_event.is_set():
        await queue.put(sequence)
        sequence += 1
        next_time = started + sequence / config.rate
        await asyncio.sleep(max(0.0, next_time - loop.time()))


async def progress_reporter(stats: Stats, interval: float, stop_event: asyncio.Event) -> None:
    """Print bounded periodic progress suitable for activity log streaming."""

    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            return
        except asyncio.TimeoutError:
            snapshot = await stats.snapshot()
            print(
                "[{now}] elapsed={elapsed:.1f}s sent={sent} completed={completed} errors={errors} avg_ms={avg:.1f}".format(
                    now=datetime.now().strftime("%H:%M:%S"),
                    elapsed=snapshot["elapsed"],
                    sent=snapshot["sent"],
                    completed=snapshot["completed"],
                    errors=snapshot["errors"],
                    avg=snapshot["avg_latency_ms"],
                ),
                flush=True,
            )


def install_signal_handlers(stop_event: asyncio.Event) -> None:
    """Translate Ctrl+C and SIGTERM into cooperative shutdown where supported."""

    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop_event.set)
        except NotImplementedError:
            pass


async def run_load_test(config: LoadConfig) -> tuple[Stats, bool]:
    """Coordinate production, workers, progress, and graceful shutdown."""

    stats = Stats()
    stop_event = asyncio.Event()
    install_signal_handlers(stop_event)
    queue: asyncio.Queue[int | None] = asyncio.Queue(maxsize=max(1, config.concurrency * 2))
    workers = [asyncio.create_task(worker(queue, config, stats)) for _ in range(config.concurrency)]
    reporter = asyncio.create_task(progress_reporter(stats, config.progress_interval, stop_event))
    interrupted = False
    try:
        await producer(queue, config, stop_event)
        interrupted = stop_event.is_set()
        await queue.join()
    finally:
        stop_event.set()
        await asyncio.gather(reporter, return_exceptions=True)
        for _ in workers:
            await queue.put(None)
        await queue.join()
        await asyncio.gather(*workers, return_exceptions=True)
    return stats, interrupted


def atomic_write_json(output_path: str, value: dict[str, object]) -> None:
    """Write a private JSON artifact and atomically replace any prior output."""

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        with open(temporary, "w", encoding="utf-8") as handle:
            os.chmod(temporary, 0o600)
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def build_result(
    config: LoadConfig,
    snapshot: dict[str, object],
    started_at: str,
    completed_at: str,
    interrupted: bool,
) -> dict[str, object]:
    """Build the stable version-one artifact without headers or credentials."""

    return {
        "version": 1,
        "status": "interrupted" if interrupted else "completed",
        "started_at": started_at,
        "completed_at": completed_at,
        "target": sanitize_target(config.target.url),
        "concurrency": config.concurrency,
        "requests_per_second": config.rate,
        "duration_seconds": config.duration,
        "elapsed_seconds": round(float(snapshot["elapsed"]), 6),
        "sent": snapshot["sent"],
        "completed": snapshot["completed"],
        "success": snapshot["success"],
        "failure": snapshot["failure"],
        "errors": snapshot["errors"],
        "bytes_read": snapshot["bytes_read"],
        "average_latency_ms": round(float(snapshot["avg_latency_ms"]), 6),
        "minimum_latency_ms": snapshot["min_latency_ms"],
        "maximum_latency_ms": snapshot["max_latency_ms"],
        "status_counts": snapshot["status_counts"],
    }


def build_parser() -> argparse.ArgumentParser:
    """Define the standalone safety gate and bounded load options."""

    parser = argparse.ArgumentParser(
        description="Authorized single-host HTTP GET load test for capacity assessment.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", type=parse_target, help="Target HTTP(S) URL")
    parser.add_argument(
        "--concurrency",
        type=bounded_positive_int("concurrency", MAX_CONCURRENCY),
        required=True,
        help="Maximum concurrent connections",
    )
    parser.add_argument(
        "--rate",
        type=bounded_positive_float("request rate", MAX_REQUESTS_PER_SECOND),
        required=True,
        help="Average request starts per second",
    )
    parser.add_argument(
        "--duration",
        type=bounded_positive_float("duration", MAX_DURATION_SECONDS),
        required=True,
        help="Test duration in seconds",
    )
    parser.add_argument("--timeout", type=positive_float, default=10.0, help="Per-operation timeout in seconds")
    parser.add_argument("--read-limit", type=positive_int, default=1024 * 1024, help="Maximum bytes read per response")
    parser.add_argument("--progress-interval", type=positive_float, default=5.0, help="Progress update interval")
    parser.add_argument("--header", action="append", type=parse_header, default=[], help='Extra "Name: value" header')
    parser.add_argument("--user-agent", action="append", default=[], help="Repeat to rotate User-Agent values")
    parser.add_argument("--user-agents-file", help="One User-Agent per line")
    parser.add_argument("--insecure-tls", action="store_true", help="Disable TLS verification for an internal target")
    parser.add_argument("--json-output", help="Atomically write a machine-readable result")
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="Confirm ownership or explicit written permission for the target",
    )
    return parser


def print_start(config: LoadConfig) -> None:
    """Print the legal notice and deterministic start parameters."""

    print(LEGAL_DISCLAIMER)
    print("\nStarting authorized HTTP load test")
    print(f"Start time: {utc_now()}")
    print(f"Target: {sanitize_target(config.target.url)}")
    print(f"Concurrency: {config.concurrency}")
    print(f"Request rate: {config.rate:g} requests/second")
    print(f"Duration: {config.duration:g} seconds")
    print("Network source: this host's normal operating-system routing only")
    print()


def print_summary(snapshot: dict[str, object], interrupted: bool) -> None:
    """Print final aggregate statistics without per-request sensitive details."""

    print("\nLoad test summary")
    print(f"Status: {'interrupted' if interrupted else 'completed'}")
    print(f"Elapsed: {snapshot['elapsed']:.2f} seconds")
    print(f"Requests sent: {snapshot['sent']}")
    print(f"Responses completed: {snapshot['completed']}")
    print(f"Successful HTTP responses: {snapshot['success']}")
    print(f"HTTP failure responses: {snapshot['failure']}")
    print(f"Network/protocol errors: {snapshot['errors']}")
    print(f"Average response time: {snapshot['avg_latency_ms']:.2f} ms")
    print(f"HTTP status counts: {snapshot['status_counts']}")
    print("Educational/authorized use only. Do not test systems without explicit permission.")


async def async_main(argv: list[str]) -> int:
    """Parse options, enforce authorization, execute, and optionally persist JSON."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.i_own_this_target:
        print(LEGAL_DISCLAIMER, file=sys.stderr)
        print("\nERROR: Refusing to run without --i-own-this-target.", file=sys.stderr)
        return 2

    config = LoadConfig(
        target=args.target,
        concurrency=args.concurrency,
        rate=args.rate,
        duration=args.duration,
        timeout=args.timeout,
        read_limit=args.read_limit,
        progress_interval=args.progress_interval,
        headers=tuple(args.header),
        user_agents=load_user_agents(args.user_agent, args.user_agents_file),
        ssl_context=make_ssl_context(args.insecure_tls) if args.target.scheme == "https" else None,
    )
    print_start(config)
    started_at = utc_now()
    stats, interrupted = await run_load_test(config)
    completed_at = utc_now()
    snapshot = await stats.snapshot()
    print_summary(snapshot, interrupted)
    if args.json_output:
        atomic_write_json(args.json_output, build_result(config, snapshot, started_at, completed_at, interrupted))
    return 130 if interrupted else 0


def main() -> int:
    """Run the asyncio entry point and preserve a conventional interrupt code."""

    try:
        return asyncio.run(async_main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\nInterrupted by user. Shutting down gracefully.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

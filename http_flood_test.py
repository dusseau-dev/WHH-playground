#!/usr/bin/env python3
"""
Authorized single-host HTTP load testing and capacity assessment tool.

This script is intended for security engineers, site owners, and operators who
need to understand how their own web server responds to sustained HTTP GET
traffic from one client machine. It is for educational and authorized use only.

Important boundaries:
- Only run this against systems you own or have explicit written permission to
  test.
- This is a single-host load test. It does not use multiple IP addresses,
  botnets, proxy rotation, or source-address spoofing.
- The required --i-own-this-target flag is a deliberate safety gate. It is not
  proof of authorization; it is a reminder that authorization is mandatory.
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import ssl
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlsplit


LEGAL_DISCLAIMER = """
LEGAL NOTICE:
  This tool generates HTTP load and must only be used against systems you own
  or have explicit written permission to test. Unauthorized load testing may be
  illegal and may disrupt services. You are responsible for choosing safe test
  parameters and for coordinating with affected operators.
""".strip()

DEFAULT_USER_AGENT = "http_flood_test/1.0 authorized-single-host-load-test"

# Headers that should remain controlled by this client so it can produce valid,
# bounded, GET-only requests. User-Agent is handled through --user-agent.
RESERVED_HEADERS = {
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "user-agent",
}


@dataclass(frozen=True)
class Target:
    """Normalized target URL parts needed to open a socket and build a request."""

    url: str
    scheme: str
    host: str
    host_header: str
    port: int
    path_and_query: str
    tls_server_name: str | None


@dataclass(frozen=True)
class LoadConfig:
    """All runtime options needed by producers, workers, and request senders."""

    target: Target
    concurrency: int
    rate: float
    duration: float
    timeout: float
    read_limit: int
    progress_interval: float
    headers: tuple[tuple[str, str], ...]
    user_agents: tuple[str, ...]
    insecure_tls: bool
    ssl_context: ssl.SSLContext | None


@dataclass
class Stats:
    """
    Shared test metrics.

    The asyncio lock keeps updates coherent even when many worker coroutines
    complete at the same time.
    """

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

            # For this report, 2xx and 3xx are considered successful HTTP
            # outcomes. 4xx/5xx responses are counted as completed failures.
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
    """argparse validator for positive integer settings."""

    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def positive_float(value: str) -> float:
    """argparse validator for positive floating point settings."""

    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def parse_target(raw_url: str) -> Target:
    """Validate and normalize the target URL for a direct HTTP(S) socket."""

    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise argparse.ArgumentTypeError("target URL must use http:// or https://")
    if not parsed.hostname:
        raise argparse.ArgumentTypeError("target URL must include a hostname")
    if parsed.username or parsed.password:
        raise argparse.ArgumentTypeError("target URL must not include embedded credentials")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    default_port = 443 if parsed.scheme == "https" else 80
    host_for_header = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    host_header = host_for_header if port == default_port else f"{host_for_header}:{port}"

    return Target(
        url=raw_url,
        scheme=parsed.scheme,
        host=parsed.hostname,
        host_header=host_header,
        port=port,
        path_and_query=path,
        tls_server_name=parsed.hostname if parsed.scheme == "https" else None,
    )


def parse_header(value: str) -> tuple[str, str]:
    """
    Parse one --header value.

    The accepted form is "Name: value". A small reserved list is rejected so the
    script remains a simple, honest, single-host GET load test.
    """

    if ":" not in value:
        raise argparse.ArgumentTypeError('headers must use the form "Name: value"')
    name, header_value = value.split(":", 1)
    name = name.strip()
    header_value = header_value.strip()
    if not name or not header_value:
        raise argparse.ArgumentTypeError("header name and value must both be non-empty")
    if name.lower() in RESERVED_HEADERS:
        raise argparse.ArgumentTypeError(f"{name!r} is managed by this tool and cannot be set with --header")
    return name, header_value


def load_user_agents(values: Iterable[str], filename: str | None) -> tuple[str, ...]:
    """
    Build the User-Agent rotation list from repeated flags and/or a file.

    The file format is one User-Agent per line. Blank lines and comment lines
    beginning with # are ignored.
    """

    user_agents = [value.strip() for value in values if value.strip()]
    if filename:
        with open(filename, "r", encoding="utf-8") as handle:
            for line in handle:
                candidate = line.strip()
                if candidate and not candidate.startswith("#"):
                    user_agents.append(candidate)
    return tuple(user_agents or [DEFAULT_USER_AGENT])


def build_request(config: LoadConfig, sequence: int) -> bytes:
    """Create one HTTP/1.1 GET request for the target and selected headers."""

    user_agent = config.user_agents[sequence % len(config.user_agents)]
    lines = [
        f"GET {config.target.path_and_query} HTTP/1.1",
        f"Host: {config.target.host_header}",
        f"User-Agent: {user_agent}",
        "Accept: */*",
        "Connection: close",
    ]
    for name, value in config.headers:
        lines.append(f"{name}: {value}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("utf-8")


def make_ssl_context(insecure_tls: bool) -> ssl.SSLContext | None:
    """Return an SSL context for HTTPS targets, optionally disabling verification."""

    if insecure_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return ssl.create_default_context()


def parse_status_code(header_block: bytes) -> int:
    """Extract the HTTP status code from the response status line."""

    first_line = header_block.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    parts = first_line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ValueError(f"invalid HTTP status line: {first_line!r}")
    return int(parts[1])


async def read_response(reader: asyncio.StreamReader, timeout: float, read_limit: int) -> tuple[int, int]:
    """
    Read response headers and up to read_limit bytes of response data.

    The read limit prevents the client from buffering very large responses. The
    request is still a GET, but the client closes the socket after the limit.
    """

    header_block = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
    status_code = parse_status_code(header_block)
    total_read = len(header_block)
    remaining = max(0, read_limit - total_read)

    while remaining > 0:
        chunk = await asyncio.wait_for(reader.read(min(65536, remaining)), timeout=timeout)
        if not chunk:
            break
        total_read += len(chunk)
        remaining -= len(chunk)

    return status_code, total_read


async def send_one_request(config: LoadConfig, sequence: int, stats: Stats) -> None:
    """
    Open one connection, send one GET request, record its outcome, and close it.

    No source address is spoofed. asyncio.open_connection uses the operating
    system's normal local routing and source address selection.
    """

    await stats.record_sent()
    started = time.perf_counter()
    writer: asyncio.StreamWriter | None = None

    try:
        ssl_context = config.ssl_context
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                config.target.host,
                config.target.port,
                ssl=ssl_context,
                server_hostname=config.target.tls_server_name if ssl_context else None,
                limit=max(65536, config.read_limit),
            ),
            timeout=config.timeout,
        )

        writer.write(build_request(config, sequence))
        await asyncio.wait_for(writer.drain(), timeout=config.timeout)

        status_code, bytes_read = await read_response(reader, config.timeout, config.read_limit)
        latency_ms = (time.perf_counter() - started) * 1000
        await stats.record_response(status_code, latency_ms, bytes_read)
    except Exception:
        # Errors are intentionally summarized rather than printed per request;
        # printing every exception can dominate the load test and make terminal
        # output unreadable. The periodic and final summaries include counts.
        await stats.record_error()
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def worker(name: int, queue: asyncio.Queue[int | None], config: LoadConfig, stats: Stats) -> None:
    """Consume scheduled request numbers and execute them one at a time."""

    while True:
        sequence = await queue.get()
        try:
            if sequence is None:
                return
            await send_one_request(config, sequence, stats)
        finally:
            queue.task_done()


async def producer(queue: asyncio.Queue[int | None], config: LoadConfig, stop_event: asyncio.Event) -> None:
    """
    Schedule requests at the configured average rate until duration expires.

    Backpressure from the bounded queue means the tool will not build an
    unbounded backlog if the target or local machine cannot keep up.
    """

    loop = asyncio.get_running_loop()
    start = loop.time()
    end = start + config.duration
    sequence = 0

    while loop.time() < end and not stop_event.is_set():
        await queue.put(sequence)
        sequence += 1

        # Use absolute scheduling to avoid accumulating sleep drift over time.
        next_time = start + (sequence / config.rate)
        await asyncio.sleep(max(0.0, next_time - loop.time()))


async def progress_reporter(stats: Stats, interval: float, stop_event: asyncio.Event) -> None:
    """Print periodic one-line progress updates while the test is running."""

    while not stop_event.is_set():
        await asyncio.sleep(interval)
        snapshot = await stats.snapshot()
        print(
            "[{time}] elapsed={elapsed:.1f}s sent={sent} completed={completed} "
            "success={success} failures={failure} errors={errors} avg_ms={avg:.1f}".format(
                time=datetime.now().strftime("%H:%M:%S"),
                elapsed=snapshot["elapsed"],
                sent=snapshot["sent"],
                completed=snapshot["completed"],
                success=snapshot["success"],
                failure=snapshot["failure"],
                errors=snapshot["errors"],
                avg=snapshot["avg_latency_ms"],
            ),
            flush=True,
        )


def install_signal_handlers(stop_event: asyncio.Event) -> None:
    """Install Ctrl+C/SIGTERM handlers when supported by the event loop."""

    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop_event.set)
        except NotImplementedError:
            # Some Windows event loops do not support add_signal_handler.
            pass


async def run_load_test(config: LoadConfig) -> Stats:
    """Coordinate request production, workers, progress reporting, and shutdown."""

    stats = Stats()
    stop_event = asyncio.Event()
    install_signal_handlers(stop_event)

    # The bounded queue prevents runaway memory use when the configured rate is
    # higher than the configured concurrency can actually process.
    queue: asyncio.Queue[int | None] = asyncio.Queue(maxsize=max(1, config.concurrency * 2))
    workers = [asyncio.create_task(worker(index, queue, config, stats)) for index in range(config.concurrency)]
    reporter = asyncio.create_task(progress_reporter(stats, config.progress_interval, stop_event))

    try:
        await producer(queue, config, stop_event)
        await queue.join()
    finally:
        stop_event.set()
        reporter.cancel()
        await asyncio.gather(reporter, return_exceptions=True)

        for _ in workers:
            await queue.put(None)
        await queue.join()
        await asyncio.gather(*workers, return_exceptions=True)

    return stats


def build_parser() -> argparse.ArgumentParser:
    """Define the command-line interface."""

    parser = argparse.ArgumentParser(
        description="Authorized single-host HTTP GET load test for capacity assessment.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", type=parse_target, help="Target HTTP(S) URL")
    parser.add_argument("--concurrency", type=positive_int, required=True, help="Maximum concurrent connections")
    parser.add_argument("--rate", type=positive_float, required=True, help="Average request start rate per second")
    parser.add_argument("--duration", type=positive_float, required=True, help="Test duration in seconds")
    parser.add_argument("--timeout", type=positive_float, default=10.0, help="Per-connect/read/write timeout in seconds")
    parser.add_argument(
        "--read-limit",
        type=positive_int,
        default=1024 * 1024,
        help="Maximum response bytes to read per request before closing the socket",
    )
    parser.add_argument(
        "--progress-interval",
        type=positive_float,
        default=5.0,
        help="Seconds between progress updates",
    )
    parser.add_argument(
        "--header",
        action="append",
        type=parse_header,
        default=[],
        help='Extra request header, repeatable, for example: --header "Accept-Language: en-US"',
    )
    parser.add_argument(
        "--user-agent",
        action="append",
        default=[],
        help="User-Agent value, repeatable. Multiple values are rotated across requests.",
    )
    parser.add_argument("--user-agents-file", help="File containing one User-Agent per line")
    parser.add_argument(
        "--insecure-tls",
        action="store_true",
        help="Disable TLS certificate verification for authorized internal targets",
    )
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="Required safety gate confirming you own or have written permission to test the target",
    )
    return parser


def print_start(config: LoadConfig) -> None:
    """Print the deterministic startup information requested by the prompt."""

    print(LEGAL_DISCLAIMER)
    print()
    print("Starting authorized HTTP load test")
    print(f"Start time: {datetime.now(timezone.utc).isoformat()}")
    print(f"Target: {config.target.url}")
    print(f"Concurrency: {config.concurrency}")
    print(f"Request rate: {config.rate:g} requests/second")
    print(f"Duration: {config.duration:g} seconds")
    print(f"Timeout: {config.timeout:g} seconds")
    print(f"Extra headers: {len(config.headers)}")
    print(f"User-Agent values: {len(config.user_agents)}")
    print("Source addresses: local operating system default only; no spoofing or IP rotation")
    print()


def print_summary(stats: Stats, snapshot: dict[str, object]) -> None:
    """Print final test metrics."""

    status_counts = snapshot["status_counts"]
    print()
    print("Load test summary")
    print(f"Elapsed: {snapshot['elapsed']:.2f} seconds")
    print(f"Requests sent: {snapshot['sent']}")
    print(f"Responses completed: {snapshot['completed']}")
    print(f"Successful HTTP responses (2xx/3xx): {snapshot['success']}")
    print(f"HTTP failure responses (4xx/5xx/other): {snapshot['failure']}")
    print(f"Network/protocol errors: {snapshot['errors']}")
    print(f"Bytes read: {snapshot['bytes_read']}")
    print(f"Average response time: {snapshot['avg_latency_ms']:.2f} ms")

    min_latency = snapshot["min_latency_ms"]
    max_latency = snapshot["max_latency_ms"]
    if min_latency is not None:
        print(f"Minimum response time: {min_latency:.2f} ms")
    if max_latency is not None:
        print(f"Maximum response time: {max_latency:.2f} ms")
    print(f"HTTP status counts: {status_counts}")

    if stats.errors:
        print("Note: errors include connection, TLS, timeout, malformed response, and interrupted request failures.")
    print("Educational/authorized use only. Do not run against systems without explicit permission.")


async def async_main(argv: list[str]) -> int:
    """Parse arguments, enforce the safety gate, and run the assessment."""

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
        insecure_tls=args.insecure_tls,
        ssl_context=make_ssl_context(args.insecure_tls) if args.target.scheme == "https" else None,
    )

    print_start(config)
    stats = await run_load_test(config)
    print_summary(stats, await stats.snapshot())
    return 0


def main() -> int:
    """Entry point that handles Ctrl+C cleanly."""

    try:
        return asyncio.run(async_main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\nInterrupted by user. Shutting down gracefully.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

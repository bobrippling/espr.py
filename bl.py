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
import logging
from bluepy import btle

log_levels = {
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
    "none": logging.CRITICAL,
}

logging.basicConfig(level=logging.INFO)

class UART_Delegate(btle.DefaultDelegate):
    def __init__(self):
        btle.DefaultDelegate.__init__(self)
        self.buf = b''

    def handleNotification(self, c_handle, data):
        self.buf += data


class EvalTimeout(TimeoutError):
    def __init__(self, desc, rxbuf, *args):
        TimeoutError.__init__(self, desc, *args)
        self.rxbuf = rxbuf

    def __str__(self):
        return "\n".join([
            TimeoutError.__str__(self),
            f"rxbuf was: {self.rxbuf}"
        ])

# \x03 = Ctrl-C
# \x10 = echo off (current line)
class Connection:
    def __init__(self, addr, delegate=None):
        self.peripheral = btle.Peripheral(addr, "random")

        self.rx = delegate if delegate else UART_Delegate()
        self.peripheral.setDelegate(self.rx)

        self.nuart = self.peripheral.getServiceByUUID(btle.UUID("6E400001-B5A3-F393-E0A9-E50E24DCCA9E"))
        self.nuart_tx = self.nuart.getCharacteristics(btle.UUID("6E400002-B5A3-F393-E0A9-E50E24DCCA9E"))[0]
        self.nuart_rx = self.nuart.getCharacteristics(btle.UUID("6E400003-B5A3-F393-E0A9-E50E24DCCA9E"))[0]

        nuart_rxnotifyhandle = self.nuart_rx.getHandle() + 1
        self.peripheral.writeCharacteristic(nuart_rxnotifyhandle, b"\x01\x00", withResponse=True)

        # check connection:
        if delegate is None: # using UART_Delegate, check:
            r = ""
            for _ in range(2):
                try:
                    r = self.eval("1+1")
                    if r == "2":
                        # FIXME: reset() to halt any interrupts/setTimeouts?
                        break
                except EvalTimeout as e: # TODO: maybe move this into eval, interrupt on any eval
                    print(f"! {e}")
                print("! interrupting...", file=sys.stderr)
                self.send_bytes(b"\x03")
                self.wait(.1)
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
                raise EvalTimeout("Couldn't eval", self.rx.buf)
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
    print(f"{sys.argv[0]} daemon <address>")
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

    elif argv[0] == "daemon":
        if len(argv) != 2:
            usage()

        addr = argv[1]
        daemon(addr)

    else:
        usage()

def daemon(addr):
    import json

    class LineDelegate(btle.DefaultDelegate):
        def __init__(self, log_transport, log_reqs):
            btle.DefaultDelegate.__init__(self)
            self.buf = b''
            self.conn = None
            self.log_transport = log_transport
            self.log_reqs = log_reqs

        def handleNotification(self, c_handle, data):
            self.buf += data

            while True:
                try:
                    i = self.buf.index(b"\n")
                except ValueError:
                    break

                line = self.buf[:i]
                self.buf = self.buf[i+1:]
                self.handleLine(line)

        def handleLine(self, line):
            self.log_transport.info(f"line: {line}")
            try:
                j = json.loads(line)
            except json.decoder.JSONDecodeError:
                return

            if j.get("t") != "http":
                return

            self.handleHttp(j)

        def handleHttp(self, req):
            self.log_reqs.debug(f"req: {req}")

            resp = {
                "id": req["id"],
                #err: "...",
                "s": "echo:" + json.dumps(req.get("body")),
            }

            out = self.conn.eval(f"Bangle.httpResp({json.dumps(resp)})")

            self.log_reqs.info(f"req dispatch: {out}")

    log_transport = logging.getLogger("transport")
    log_reqs = logging.getLogger("requests")

    logenv = os.environ.get("BL_LOG")
    if logenv:
        for ent in logenv.split(","):
            mod_lvl = ent.split("=", maxsplit=1)
            if len(mod_lvl) == 1:
                mod = mod_lvl
                lvl = "info"
            else:
                assert len(mod_lvl) == 2
                mod, lvl = mod_lvl

            lvl_val = log_levels.get(lvl)
            if not lvl_val:
                logging.error(f"Invalid log level \"{lvl}\"")
                sys.exit(2)

            if mod == "transport":
                logger = log_transport
            elif mod == "requests":
                logger = log_reqs
            else:
                logging.error(f"Invalid log module \"{mod}\"")
                sys.exit(2)

            print(f"set {mod} to {lvl}")
            logger.setLevel(lvl_val)

    while True:
        delegate = LineDelegate(log_transport, log_reqs)
        try:
            conn = Connection(addr, delegate)
        except btle.BTLEDisconnectError as e:
            logging.warning("connect:", e)
            time.sleep(30)
            continue
        delegate.conn = conn

        logging.info(f"connected to {addr}")

        while True:
            try:
                conn.wait(10.0)
            except EvalTimeout as e:
                logging.warning(f"timeout: {e}")
                break


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

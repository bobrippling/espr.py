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
import subprocess
import time
import select
import pathlib
import json
import base64
import logging
import json
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
        try:
            self.peripheral = btle.Peripheral(addr, "public")
        except btle.BTLEDisconnectError as e:
            try:
                self.peripheral = btle.Peripheral(addr, "random")
                logging.info(f"connect failed using public, used random address instead")
            except btle.BTLEDisconnectError:
                raise

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
            for _ in range(4):
                try:
                    r = self.eval("1+1")
                    if r == "2":
                        # FIXME: reset() to halt any interrupts/setTimeouts?
                        break
                except EvalTimeout as e: # TODO: maybe move this into eval, interrupt on any eval
                    print(f"! {e}")
                    print(f"! rxbuf for above: {r}")
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

class LineDelegate(btle.DefaultDelegate):
    def __init__(self, log_transport, log_reqs, log_actions):
        btle.DefaultDelegate.__init__(self)
        self.buf = b''
        self.conn = None
        self.log_transport = log_transport
        self.log_reqs = log_reqs
        self.log_actions = log_actions

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

        try:
            t = j.get("t")

            if t == "http":
                self.handleHttp(j)
            elif t == "intent":
                self.handleIntent(j)
        except Exception as e:
            self.log_transport.error(str(e))
            return

    def handleHttp(self, req):
        self.log_reqs.debug(f"req: {req}")

        resp = {
            "id": req["id"],
            #err: "...",
            "s": "echo:" + json.dumps(req.get("body")),
        }

        out = self.conn.eval(f"Bangle.httpResp({json.dumps(resp)})")

        self.log_reqs.info(f"req dispatch: {out}")

    def handleIntent(self, req):
        self.log_reqs.debug(f"req: {req}")

        # pretend to be GB
        # no response, just handle the intent
        action = req.get("action")

        if action.startswith("com.espruino.gadgetbridge.banglejs"):
            rest = action[34:]

            if rest == ".HA":
                trigger = req["extra"]["trigger"]

                if trigger == "APP_STARTED" or trigger.startswith("TRIGGER"):
                    self.log_actions.debug(f"ignoring \"{trigger}\"")
                    return

                value = req["extra"].get("value")

                self.log_actions.info(f"triggering \"{trigger}\"{f', value={value}' if value is not None else ''}")

                if value is not None:
                    self.run(["mqtt", "brightness", trigger, str(int(255 * value / 100))])
                    return

                out = subprocess.run(["mqtt", "get", trigger], capture_output=True)
                if len(out.stderr):
                    self.log_actions.error(f"error running mqtt: {out.stderr}")
                    return
                if out.returncode != 0:
                    self.log_actions.error(f"error running mqtt, exitcode {out.returncode}")
                    return

                output = out.stdout.strip()
                if output == b'ON':
                    arg = "off"
                elif output == b'OFF':
                    arg = "on"
                else:
                    self.log_actions.error(f"unknown mqtt response {output}")
                    return

                if not self.run(["mqtt", "set", trigger, arg]):
                    return

            else:
                self.log_actions.info(f"unknown sub-intent: \"{action}\"")
            return

        self.log_actions.info(f"unknown intent: \"{action}\"")

    def run(self, cmdlist):
        out = subprocess.run(cmdlist)
        if out.returncode != 0:
            self.log_actions.error(f"error running {cmdlist[0]}, exitcode {out.returncode}")
            return False
        return True

class LogPrint:
    pending = False

    @staticmethod
    def start(desc):
        if Log.pending:
            print()
        Log.pending = True
        print(f"[.] {desc}", end="\r")

    @staticmethod
    def end(desc, success=True):
        Log.pending = False
        file = sys.stdout if success else sys.stderr
        print(f"[{'x' if success else '!'}] {desc}", file=file)
        if not success:
            global exitcode
            exitcode = 1

class LogNoop:
    @staticmethod
    def start(_): pass
    @staticmethod
    def end(_desc, success=True):
        if not success:
            global exitcode
            exitcode = 1

Log = LogPrint

def usage(extra=None):
    if extra:
        print(extra);
        print()
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

    try:
        new_contents = conn.download(fname)
    except binascii.Error as e:
        Log.end(f"Error decoding: {e}", success=False)
        return

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
        addr = None
        bdir = None
        set_time = False
        backup_json = False
        backup_health = False
        for arg in argv[1:]:
            if arg == "--quiet":
                global Log
                Log = LogNoop
            elif arg == "--set-time":
                set_time = True
            elif arg == "--json":
                backup_json = True
            elif arg == "--health":
                backup_health = True
            elif addr is None:
                addr = arg
            elif bdir is None:
                bdir = pathlib.Path(arg)
            else:
                usage(f"extra argument \"{arg}\"")

        if bdir is None:
            usage("no addr/backup dir given")
        assert addr is not None

        if not set_time and not backup_json and not backup_health:
            set_time = True
            backup_json = True
            backup_health = True

        conn = Connection(addr)

        bdir.mkdir(exist_ok=True, parents=True)

        if set_time:
            Log.start("set time")
            off = float(conn.eval("getTime()")) - time.time()
            conn.eval(f"setTime({time.time()})")
            Log.end(f"set time (offset was {off:.2f})")

        if backup_json:
            Log.start("JSON backup")
            bdir_json = bdir / "json"
            bdir_json.mkdir(exist_ok=True, parents=True)
            jsons = json.loads(conn.eval("require('Storage').list(/\\.json$/)"))
            for fname in jsons:
                backup_file(fname, bdir_json, conn)
            Log.end("JSON backup")

        if backup_health:
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
    log_transport = logging.getLogger("transport")
    log_reqs = logging.getLogger("requests")
    log_actions = logging.getLogger("actions")

    log_transport.setLevel(logging.WARNING)

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

            loggers = []
            if mod == "transport":
                loggers.append(log_transport)
            elif mod == "requests":
                loggers.append(log_reqs)
            elif mod == "actions":
                loggers.append(log_actions)
            elif mod == "all":
                loggers.extend([log_actions, log_reqs, log_transport])
            else:
                logging.error(f"Invalid log module \"{mod}\"")
                sys.exit(2)

            for logger in loggers:
                logger.setLevel(lvl_val)

    while True:
        delegate = LineDelegate(log_transport, log_reqs, log_actions)
        try:
            conn = Connection(addr, delegate)
        except btle.BTLEDisconnectError as e:
            logging.warning(f"connect: {e}")
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
            except btle.BTLEDisconnectError as e:
                logging.warning(f"wait: {e}")
                break

def main(argv):
    if len(argv) < 1:
        usage()

    try:
        command(argv)
    except btle.BTLEDisconnectError as e:
        print(f"error: {e}")
        exitcode = 1
    except KeyboardInterrupt:
        exitcode = 1

exitcode = 0

if __name__ == "__main__":
    main(sys.argv[1:])
    sys.exit(exitcode)

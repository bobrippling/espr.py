# Usage

```sh
./bl.py interact <address>
./bl.py tty <address>
./bl.py nightly [--quiet] <address> backupdir/
```

# Pairing/Bonding

Use bluetoothctl to bond a device, if it uses a random-private address:

```sh
pair <address>
disconnect
```

Confirm bonding:

```sh
devices Bonded
```

The address to use will be whatever's set, not the device's original address.

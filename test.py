from bl import Connection

class MockDelegate:
    def __init__(self):
        self.buf = b''
        self.nextbuf = None

class MockPeripheral:
    def __init__(self, delegate):
        self.delegate = delegate

    def setDelegate(self, delegate):
        pass

    def getServiceByUUID(self, uuid):
        nuart = Service()
        return nuart

    def waitForNotifications(self, time):
        if self.delegate.nextbuf:
            self.delegate.buf = self.delegate.nextbuf
            self.delegate.nextbuf = None

    def writeCharacteristic(self, handle, bytes, withResponse):
        pass

class Service:
    def getCharacteristics(self, uuid):
        return [Char()]

class Char:
    def getHandle(self):
        return 3

    def write(self, bytes):
        pass

def test_gbbefore():
    delegate = MockDelegate()
    conn = Connection("addr", delegate, MockPeripheral(delegate))

    delegate.nextbuf = b'\r\n{"t":"mock"}\r\n123\r\n>'
    gb_msgs = []

    x = conn.eval(
        "1+2",
        is_initial=True,
        on_gb=lambda m: gb_msgs.append(m)
    )

    assert x == '123'
    assert gb_msgs == [{"t": "mock"}]

test_gbbefore()

"""toto's in-container relay: the only way out of a task container.

Started by the runner with `docker exec -i <container> python3 /tmp/toto-relay.py 127.0.0.1:8080`.
It listens on that loopback address and multiplexes every connection over its own stdin/stdout
(the exec stream) to the runner, which forwards each one to the credential proxy on the host.
The container needs no network, no mount and no socket, and the credential never comes in.

Frames both ways: 9-byte header (connection id u32, type u8, payload length u32, big endian) and
payload. Types: 1 OPEN (container to runner), 2 DATA, 3 CLOSE, 4 READY (once, id 0). Python 3.8+,
standard library only, so any image that can run Omnigent can run this.
"""
import socket
import struct
import sys
import threading

HDR = struct.Struct(">IBI")
OPEN, DATA, CLOSE, READY = 1, 2, 3, 4
out = sys.stdout.buffer
out_lock = threading.Lock()
conns = {}
conns_lock = threading.Lock()


def send(cid, kind, payload=b""):
    with out_lock:
        out.write(HDR.pack(cid, kind, len(payload)) + payload)
        out.flush()


def read_exact(stream, n):
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def client(cid, sock):
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            send(cid, DATA, data)
    except OSError:
        pass
    send(cid, CLOSE)
    with conns_lock:
        conns.pop(cid, None)
    try:
        sock.close()
    except OSError:
        pass


def accept(server):
    next_id = 1
    while True:
        sock, _ = server.accept()
        cid, next_id = next_id, next_id + 1
        with conns_lock:
            conns[cid] = sock
        send(cid, OPEN)
        threading.Thread(target=client, args=(cid, sock), daemon=True).start()


def from_runner():
    inp = sys.stdin.buffer
    while True:
        hdr = read_exact(inp, HDR.size)
        if hdr is None:
            return
        cid, kind, n = HDR.unpack(hdr)
        payload = read_exact(inp, n) if n else b""
        if payload is None:
            return
        with conns_lock:
            sock = conns.get(cid)
        if sock is None:
            continue
        try:
            if kind == DATA:
                sock.sendall(payload)
            elif kind == CLOSE:
                sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def main():
    host, port = sys.argv[1].rsplit(":", 1)
    if host != "127.0.0.1":
        sys.exit("toto-relay only listens on 127.0.0.1")
    server = socket.create_server((host, int(port)))
    threading.Thread(target=accept, args=(server,), daemon=True).start()
    send(0, READY)
    from_runner()  # returns when the runner closes the stream; daemon threads die with us


if __name__ == "__main__":
    main()

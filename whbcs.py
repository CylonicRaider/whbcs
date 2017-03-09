#!/usr/bin/env python3
# -*- coding: ascii -*-

# Weird HomeBrew Chat Server

APPNAME = 'WHBCS'
VERSION = '2.0-pre'

import sys, os, re, socket
import threading
import signal
import logging

HOST = ''
PORT = 4321
REUSE_ADDR = True

GREETING = '''
# Weird HomeBrew Chat Server v%s
# Type "/help" for a command overview.
'''[1:-1]

# Spawn a new daemonic thread.
def spawn_thread(func, *args, **kwds):
    thr = threading.Thread(target=func, args=args, kwargs=kwds)
    thr.setDaemon(True)
    thr.start()
    return thr

# A string with an integer telling its position within another string.
class Token(str):
    @classmethod
    def extract(cls, string, word=r'\S+'):
        pattern, pos, ret = re.compile(word), 0, []
        while 1:
            m = pattern.search(string, pos)
            if not m: break
            ret.append(cls(m.group(), m.start()))
            pos = m.end()
        return ret

    def __new__(cls, obj, offset):
        inst = str.__new__(cls, obj)
        inst.offset = offset
        return inst

    def __repr__(self):
        return '%s(%s, %r)' % (self.__class__.__name__, str.__repr__(self),
                               self.offset)

class Server:
    class Endpoint:
        def __init__(self, server, id, sock, addr, logger=None):
            self.server = server
            self.id = id
            self.socket = sock
            self.addr = addr
            self.logger = logger
            self.file = sock.makefile('rwb')
            self.handler = DoorstepClientHandler(self)
            self.server._add_endpoint(self)

        def swap_handler(self, hnd):
            self.handler.quit(False)
            self.handler = hnd
            self.handler.init(False)

        def send(self, message):
            self.handler.send(message)

        def close(self):
            self.log('CLOSING id=%r' % self.id)
            self.server._remove_endpoint(self)
            try:
                self.handler.quit(True)
            finally:
                self.file.close()
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()

        def log(self, *args):
            if self.logger: self.logger.info(*args)

        def __call__(self):
            try:
                self.handler.init(True)
                while 1:
                    if self.handler():
                        break
            finally:
                try:
                    self.close()
                except IOError:
                    pass

    @classmethod
    def listen(cls, addr, logger=None, reuse_addr=False):
        if logger:
            logger.info('LISTENING bind=%r' % (addr,))
        s = socket.socket()
        if reuse_addr:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(addr)
        s.listen(5)
        return cls(s, logger)

    def __init__(self, socket, logger=None):
        self.socket = socket
        self.logger = logger
        self._next_connid = 0
        self.lock = threading.RLock()
        self.endpoints = []
        self.distributor = ChatDistributor(self)

    # Process a message (as a "live" data structure) from the given client.
    def handle(self, id, message):
        self.distributor.handle(id, message)

    # Broadcast a message (given as a "live" data structure) to all clients.
    def broadcast(self, message):
        with self.lock:
            es = list(self.endpoints)
        for e in es:
            e.send(message)

    def close(self):
        self.log('CLOSING')
        self.socket.close()
        with self.lock:
            es = list(self.endpoints)
        for e in es:
            e.close()

    def log(self, *args):
        if self.logger:
            self.logger.info(*args)

    def _add_endpoint(self, hnd):
        with self.lock:
            self.endpoints.append(hnd)

    def _remove_endpoint(self, hnd):
        with self.lock:
            self.endpoints.remove(hnd)

    def __call__(self):
        while 1:
            conn, addr = self.socket.accept()
            cid = self._next_connid
            self._next_connid += 1
            self.log('CONNECTION id=%r from=%r' % (cid, addr))
            spawn_thread(self.Endpoint(self, cid, conn, addr, self.logger))
            conn, addr = None, None

class ChatDistributor:
    def __init__(self, server):
        self.server = server

    def handle(self, connid, message):
        pass

class ClientHandler:
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def init(self, first):
        pass

    def send(self, message):
        raise NotImplementedError

    def quit(self, last):
        pass

    def __call__(self):
        raise NotImplementedError

class LineBasedClientHandler(ClientHandler):
    def __init__(self, endpoint):
        ClientHandler.__init__(self, endpoint)
        self.ilock = threading.RLock()
        self.olock = threading.RLock()
        self.encoding = 'ascii'
        self.errors = 'replace'

    def readline(self):
        with self.ilock:
            ln = self.endpoint.file.readline()
            return ln.decode(self.encoding, errors=self.errors)
    def readline_words(self):
        ln = self.readline()
        if not ln: return None
        return Token.extract(ln)

    def println(self, *args, **kwds):
        s = kwds.get('sep', ' ').join(args) + kwds.get('end', '\n')
        d = s.encode(self.encoding, errors=self.errors)
        with self.olock:
            self.endpoint.file.write(d)
            self.endpoint.file.flush()

class DoorstepClientHandler(LineBasedClientHandler):
    def init(self, first):
        if first: self.println(APPNAME, 'v' + VERSION)
        self.println(GREETING % VERSION)

    def send(self, message):
        pass

    def __call__(self):
        while 1:
            tokens = self.readline_words()
            if tokens is None:
                return True
            elif not tokens:
                pass
            elif tokens[0] == '/quit':
                return True
            elif tokens[0] == '/help':
                self.println('# NYI')
            else:
                self.println('FAIL', '#', 'Unknown command.')

def main():
    # Interrupt execution
    def die(msg, retcode=1):
        sys.stderr.write(msg)
        sys.stderr.flush()
        sys.exit(retcode)
    # Signal handler
    def interrupt(signo, frame):
        raise KeyboardInterrupt
    # Parse arguments
    host, port, reuse_addr, logfile = HOST, PORT, REUSE_ADDR, None
    try:
        it = iter(sys.argv[1:])
        for arg in it:
            if arg == '--help':
                die('USAGE: %s [--help] [--host host] [--port port] '
                    '[--[no-]reuseaddr] [--logfile logfile]\n'
                    'Defaults: --host %r --port %s --%sreuseaddr\n' % (
                        sys.argv[0], HOST, PORT,
                        '' if REUSE_ADDR else 'no-'), 0)
            elif arg == '--host':
                host = next(it)
            elif arg == '--port':
                port = int(next(it))
            elif arg == '--logfile':
                logfile = next(it)
            elif arg == '--reuseaddr':
                reuse_addr = True
            elif arg == '--no-reuseaddr':
                reuse_addr = False
            else:
                die('ERROR: Unrecognized argument %r\n' % arg)
    except StopIteration:
        die('ERROR: Missing required argument for option %r\n' % arg)
    except ValueError:
        die('ERROR: Incorrect argument for option %r\n' % arg)
    # Set up logging
    config = {}
    if logfile is not None: config['filename'] = logfile
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s %(name)s '
        '%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', **config)
    # Trap signals
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    # Run server
    logging.info(APPNAME + ' ' + VERSION)
    s = Server.listen((host, port), logging.getLogger(), reuse_addr)
    try:
        s()
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

if __name__ == '__main__': main()

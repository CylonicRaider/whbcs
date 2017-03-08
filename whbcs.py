#!/usr/bin/env python3
# -*- coding: ascii -*-

# Weird HomeBrew Chat Server

APPNAME = 'WHBCS'
VERSION = '2.0-pre'

import sys, os, socket
import threading
import signal
import logging

HOST = ''
PORT = 4321
REUSE_ADDR = True

def spawn_thread(func, *args, **kwds):
    thr = threading.Thread(target=func, args=args, kwargs=kwds)
    thr.setDaemon(True)
    thr.start()
    return thr

class Server:
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
        self.distributor = ChatDistributor(self)
        self.handlers = []

    # Process a message (as a "live" data structure) from the given client.
    def handle(self, id, message):
        self.distributor.handle(id, message)

    # Broadcast a message (given as a "live" data structure) to all clients.
    def broadcast(self, message):
        with self.lock:
            hl = list(self.handler)
        for h in hl:
            hl.send(message)

    def close(self):
        self.log('CLOSING')
        self.socket.close()
        with self.lock:
            hl = list(self.handlers)
        for h in hl:
            h.close()

    def log(self, *args):
        if self.logger: self.logger.info(*args)

    def _add_handler(self, hnd):
        with self.lock:
            self.handlers.append(hnd)

    def _remove_handler(self, hnd):
        with self.lock:
            self.handlers.remove(hnd)

    def __call__(self):
        while 1:
            conn, addr = self.socket.accept()
            cid = self._next_connid
            self._next_connid += 1
            self.log('CONNECTION id=%r from=%r' % (cid, addr))
            spawn_thread(ClientHandler(self, cid, conn, addr, self.logger))
            conn, addr = None, None

class ClientHandler:
    def __init__(self, server, id, sock, addr, logger=None):
        self.server = server
        self.id = id
        self.socket = sock
        self.addr = addr
        self.logger = logger
        self.file = sock.makefile('rwb')
        self.processor = DoorstepClientProcessor(self)
        self.server._add_handler(self)

    def send(self, message):
        self.file.write(self.processor.encode(message))
        self.file.flush()

    def close(self):
        self.log('CLOSING id=%r' % self.id)
        self.server._remove_handler(self)
        try:
            self.processor.handle(None)
        finally:
            self.file.close()
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()

    def log(self, *args):
        if self.logger: self.logger.info(*args)

    def __call__(self):
        try:
            while 1:
                l = self.file.readline()
                if not l: break
                self.processor.handle(l)
        finally:
            try:
                self.close()
            except IOError:
                pass

class ChatDistributor:
    def __init__(self, server):
        self.server = server

    def handle(self, connid, message):
        pass

class ClientProcessor:
    def __init__(self, handler):
        self.handler = handler

    def encode(self, message):
        raise NotImplementedError

    def handle(self, line):
        raise NotImplementedError

class DoorstepClientProcessor(ClientProcessor):
    pass

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

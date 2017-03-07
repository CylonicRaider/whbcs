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

def spawn_thread(func, *args, **kwds):
    thr = threading.Thread(target=func, args=args, kwargs=kwds)
    thr.setDaemon(True)
    thr.start()
    return thr

class ClientHandler:
    def __init__(self, server, id, sock, addr, logger=None):
        self.server = server
        self.id = id
        self.socket = sock
        self.addr = addr
        self.logger = logger
        self.server._add_handler(self)

    def close(self):
        self.log('CLOSING id=%r' % self.id)
        self.server._remove_handler(self)
        self.socket.close()

    def log(self, *args):
        if self.logger: self.logger.info(*args)

    def __call__(self):
        self.close()

class Server:
    @classmethod
    def listen(cls, addr, logger=None):
        if logger:
            logger.info('LISTENING bind=%r' % (addr,))
        s = socket.socket()
        s.bind(addr)
        s.listen(5)
        return cls(s, logger)

    def __init__(self, socket, logger=None):
        self.socket = socket
        self.logger = logger
        self._next_connid = 0
        self.lock = threading.RLock()
        self.handlers = []

    def close(self):
        self.log('CLOSING')
        self.socket.close()
        with self.lock:
            hl = list(self.handlers)
        for h in hl: h.close()

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
    host, port, logfile = HOST, PORT, None
    try:
        it = iter(sys.argv[1:])
        for arg in it:
            if arg == '--help':
                die('USAGE: %s [--help] [--host host] [--port port] '
                    '[--logfile logfile]\n' % sys.argv[0], 0)
            elif arg == '--host':
                host = next(it)
            elif arg == '--port':
                port = int(next(it))
            elif arg == '--logfile':
                logfile = next(it)
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
    s = Server.listen((host, port), logging.getLogger())
    try:
        s()
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

if __name__ == '__main__': main()

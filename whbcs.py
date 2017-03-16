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

# Silence any non-critical exception during the call of func and return
# it instead.
def silence(func, *args, **kwds):
    try:
        func(*args, **kwds)
    except Exception as exc:
        return exc

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

    @classmethod
    def split(cls, string, sep=r'\s+'):
        pattern, pos, ret = re.compile(sep), 0, []
        while 1:
            m = pattern.search(string, pos)
            if not m: break
            ret.append(cls(string[pos:m.start()], pos))
            pos = m.end()
        if string[pos:]: ret.append(cls(string[pos:], pos))
        return ret

    def __new__(cls, obj, offset):
        inst = str.__new__(cls, obj)
        inst.offset = offset
        return inst

    def __repr__(self):
        return '%s(%s, %r)' % (self.__class__.__name__, str.__repr__(self),
                               self.offset)

# Error registry.
ERRORS = {
    'BADVAL': 'Bad value.',
    'NOCLNT': 'No such client.',
    'NOVAL': 'Variable has no value.',
    'NOVAR': 'No such variable.',
    'VARPRIV': 'Variable is private.',
    'VARRO': 'Variable is read-only.',
    }
def make_error(code, wrap=False):
    err = {'type': 'error', 'code': code, 'text': ERRORS[code]}
    return {'type': 'failure', 'content': err} if wrap else err

# Server socket processing.
# Responsible for accepting connections, logging those, spawning Endpoint-s
# for them.
class Server:
    # Client connection processing.
    # Little own functionality.
    class Endpoint:
        def __init__(self, server, id, sock, addr):
            self.server = server
            self.id = id
            self.socket = sock
            self.addr = addr
            self.file = sock.makefile('rwb')
            self.handler = server.distributor._make_handler(self)

        def close(self):
            self.server.log('CLOSING id=%r' % self.id)
            silence(self.socket.shutdown, socket.SHUT_RD)
            silence(self.file.flush)
            silence(self.socket.shutdown, socket.SHUT_WR)
            silence(self.socket.close)

        def __call__(self):
            self.handler()

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
        self.distributor = ChatDistributor(self)

    def log(self, *args):
        if self.logger:
            self.logger.info(*args)

    def close(self):
        self.log('CLOSING')
        silence(self.socket.close)
        self.distributor.close()
        self.log('CLOSED')

    def __call__(self):
        while 1:
            conn, addr = self.socket.accept()
            cid = self._next_connid
            self._next_connid += 1
            self.log('CONNECTION id=%r from=%r' % (cid, addr))
            spawn_thread(self.Endpoint(self, cid, conn, addr))
            conn, addr = None, None

# Chat nexus.
# Responsible for keeping track of ClientHandlers and routing messages
# between them.
class ChatDistributor:
    # Individual client processor.
    # Responsible for the management of client state independently from the
    # mode of connection.
    class ClientHandler:
        VARS = {'nick': {'type': str, 'private': False},
                'term': {'type': str, 'private': True},
                'send-text': {'type': bool, 'private': True, 'default': True}}

        def __init__(self, distributor, endpoint):
            self.distributor = distributor
            self.endpoint = endpoint
            self.id = endpoint.id
            self.vars = {k: v['default'] for k, v in self.VARS.items()
                         if 'default' in v}
            self.discipline = DoorstepLineDiscipline(self)
            distributor._add_handler(self)

        def deliver(self, message):
            self.discipline.deliver(message)

        def submit(self, message):
            def reply(msg):
                if message.get('seq'): msg['seq'] = message['seq']
                self.deliver(msg)
            if message['type'] == 'query':
                reply(self.query_var(message['content']))
            elif message['type'] == 'update':
                reply(self.update_var(message['content']))
            else:
                self.distributor.handle(message)

        def close(self):
            silence(self.discipline.quit, True)
            self.distributor._remove_handler(self)
            self.endpoint.close()

        def __call__(self):
            try:
                self.discipline.init(True)
                while 1:
                    repl = self.discipline()
                    if repl is None: break
                    self.discipline.quit(False)
                    self.discipline = repl
                    self.discipline.init(False)
            finally:
                self.close()

        def query_var(self, variable):
            try:
                desc = self.VARS[variable['name']]
            except KeyError:
                return make_error('NOVAR', True)
            cltid = variable.get('id', self.id)
            if cltid != self.id and desc['private']:
                return make_error('VARPRIV', True)
            try:
                hnd = self.distributor.get_handler(cltid)
            except KeyError:
                return make_error('NOCLNT', True)
            try:
                value = hnd.vars[variable['name']]
            except KeyError:
                return make_error('NOVAL', True)
            return {'type': 'success', 'content': {'type': 'variable',
                'id': cltid, 'name': variable['name'], 'value': value}}

        def update_var(self, variable):
            try:
                desc = self.VARS[variable['name']]
            except KeyError:
                return make_error('NOVAR', True)
            cltid = variable.get('id', self.id)
            if cltid != self.id:
                return make_error('VARRO', True)
            try:
                value = desc['type'](variable['value'])
            except ValueError:
                return make_error('BADVAL', True)
            oldvar = {'type': 'variable', 'id': self.id,
                      'name': variable['name']}
            try:
                oldvar['value'] = self.vars[variable['name']]
            except KeyError:
                pass
            self.vars[variable['name']] = value
            return {'type': 'updated', 'from': oldvar,
                'content': dict(oldvar, value=value)}

    def __init__(self, server):
        self.server = server
        self.handlers = {}
        self.lock = threading.RLock()

    def _make_handler(self, endpoint):
        return self.ClientHandler(self, endpoint)
    def _add_handler(self, hnd):
        with self.lock:
            self.handlers[hnd.id] = hnd
    def _remove_handler(self, hnd):
        with self.lock:
            del self.handlers[hnd.id]
    def get_handler(self, id):
        with self.lock:
            return self.handlers[id]

    def handle(self, connid, message):
        pass

    def broadcast(self, message):
        with self.lock:
            hnds = tuple(self.handlers.values())
        for h in hnds:
            h.deliver(message)

    def close(self):
        with self.lock:
            hnds = tuple(self.handlers.values())
        for h in hnds:
            h.close()

# Line discipline (not really).
# Responsible for the actual formatting of IO. May be dynamically swapped
# over the lifetime of a connection.
# Must ensure outgoing messages are well-formed, and can assume that for
# incoming ones in exchange.
class LineDiscipline:
    def __init__(self, handler):
        self.handler = handler
        self.ilock = threading.RLock()
        self.olock = threading.RLock()
        self.encoding = None
        self.errors = None

    def read(self, amount=-1):
        with self.ilock:
            d = self.handler.endpoint.file.read(amount)
            if self.encoding:
                return d.decode(self.encoding, errors=self.errors)
            else:
                return d
    def readline(self):
        with self.ilock:
            ln = self.handler.endpoint.file.readline()
            if self.encoding:
                return ln.decode(self.encoding, errors=self.errors)
            else:
                return ln
    def readline_words(self):
        ln = self.readline()
        if not ln: return None
        return Token.extract(ln)

    def write(self, data):
        if self.encoding:
            data = data.encode(self.encoding, errors=self.errors)
        with self.olock:
            self.handler.endpoint.file.write(data)
            self.handler.endpoint.file.flush()
    def println(self, *args, **kwds):
        if self.encoding:
            d = kwds.get('sep', ' ').join(args) + kwds.get('end', '\n')
        else:
            d = kwds.get('sep', b' ').join(args) + kwds.get('end', b'\n')
        self.write(d)

    def init(self, first):
        pass

    def deliver(self, message):
        raise NotImplementedError

    def submit(self, message):
        self.handler.submit(message)

    def quit(self, last):
        pass

    def __call__(self):
        raise NotImplementedError

# Doorstep mode.
# The initial mode a connection is in; a lowest-denominator compromise
# between all clients.
class DoorstepLineDiscipline(LineDiscipline):
    HELP = (('help', '[command]', 'Display help.', ''),
            ('quit', '', 'Terminate connection.', ''),
            ('ping', '', 'Check connectivity.', ''))
    HELPDICT = {c: (a, o, d) for c, a, o, d in HELP}

    def __init__(self, endpoint):
        LineDiscipline.__init__(self, endpoint)
        self.encoding = 'ascii'
        self.errors = 'replace'

    def init(self, first):
        if first: self.println(APPNAME, 'v' + VERSION)
        self.println(GREETING % VERSION)

    def deliver(self, message):
        pass # Explicitly silenced.

    def format_help(self, cmd=None, long=False):
        sp = lambda x, s=' ': s if x else ''
        rf = lambda x: '# ' + x.replace('\n', '\n# ') + '\n' if x else '\n'
        if cmd is None:
            ret = ['# HELP\n']
            for c, a, o, d in self.HELP:
                ret.extend(('# /', c, sp(a), a, sp(o, ' -- '), o, '\n'))
                if long and d: ret.append(rf(d))
            return ''.join(ret).rstrip('\n')
        elif long:
            a, o, d = self.HELPDICT[cmd]
            return ('# USAGE: /%s%s%s%s%s%s%s' % (cmd, sp(a), a,
                sp(o, ' -- '), o, sp(d, '\n'), rf(d))).rstrip('\n')
        else:
            a, o, d = self.HELPDICT[cmd]
            return '# USAGE: /%s%s%s' % (cmd, sp(a), a)

    def __call__(self):
        def usage():
            self.println('FAIL', self.format_help(tokens[0].lstrip('/')))
        while 1:
            tokens = self.readline_words()
            if tokens is None:
                return None
            elif not tokens:
                pass
            elif tokens[0] == '/help':
                if len(tokens) == 1:
                    self.println('OK', self.format_help(None, True))
                elif len(tokens) == 2:
                    cmd = tokens[1]
                    if cmd.startswith('/'):
                        cmd = cmd[1:]
                    if cmd in self.HELPDICT:
                        self.println('OK', self.format_help(tokens[1], True))
                    else:
                        self.println('FAIL', '#', 'Unknown command /%s.' %
                                     cmd)
                else:
                    usage()
            elif tokens[0] == '/quit':
                if len(tokens) != 1:
                    usage()
                    continue
                return None
            elif tokens[0] == '/ping':
                if len(tokens) != 1:
                    usage()
                    continue
                self.println('PONG')
            elif tokens[0].startswith('/'):
                self.println('FAIL', '#', 'Unknown command %s.' % tokens[0])
            else:
                self.println('FAIL', '#', 'Join room to start chatting.')

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

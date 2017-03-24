#!/usr/bin/env python3
# -*- coding: ascii -*-

# Weird HomeBrew Chat Server

APPNAME = 'WHBCS'
VERSION = '2.0-pre'

import sys, os, re, time, socket
import threading
import errno, signal
import logging

try:
    import Queue as queue
except ImportError:
    import queue

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
    'AJOINED': 'Already joined.',
    'ALEFT': 'Already left.',
    'BADVAL': 'Bad value.',
    'INTER': 'Internal error?!',
    'NOCLNT': 'No such client.',
    'NORDY': 'Not ready.',
    'NOTYPE': 'No such message type.',
    'NOVAL': 'Variable has no value.',
    'NOVAR': 'No such variable.',
    'VARPRIV': 'Variable is private.',
    'VARRO': 'Variable is read-only.',
    }
def make_error(code, wrap=False):
    err = {'type': 'error', 'code': code, 'content': ERRORS[code]}
    return {'type': 'failure', 'content': err} if wrap else err

# Text member generation.
def _mkhl(v, t): return {'type': 'hl', 'variant': v, 'text': t}
_star, _stars = _mkhl('msgpad', '*'), _mkhl('syspad', '***')
def _format_ok(obj):
    if obj['content']:
        return {'prefix': (_mkhl('reply', 'OK'), ' ')}
    else:
        return {'text': _mkhl('reply', 'OK')}
def _format_updated(obj):
    if obj['content']['variant'] == 'nick' and 'content' in obj['from']:
        format_text(obj['from'])
        return {'prefix': (_star, ' '), 'text': _mkhl('msgtext',
              (obj['from'], ' is now ', obj['content']))}
    else:
        return {'text': None}
def _format_post(obj):
    format_text(obj['sender'])
    if obj['variant'] == 'emote':
        return {'prefix': (_star, ' ', obj['sender'], ' ')}
    else:
        return {'prefix': (_mkhl('chatpad', '<'), obj['sender'],
                           _mkhl('chatpad', '>'), ' ')}
OBJECT_TEXTS = {
    'pong': {'prefix': _mkhl('reply', 'PONG')},
    'success': {'func': _format_ok},
    'failure': {'prefix': (_mkhl('reply', 'FAIL'), ' ',
                           _mkhl('replypad', '#'), ' ')},
    'updated': {'func': _format_updated},
    'joined': {
        'prefix': (_star, ' '),
        'suffix': (' ', _mkhl('msgtext', 'has joined'))
    },
    'left': {
        'prefix': (_star, ' '),
        'suffix': (' ', _mkhl('msgtext', 'has left')),
        'variant': {
            'abrupt': {
                'prefix': (_star, ' '),
                'suffix': (' ', _mkhl('msgerr', 'has left unexpectedly'))
            }
        }
    },
    'sysmsg': {'prefix': (_stars, ' ')},
    'post': {'func': _format_post}}
def format_text(obj, _table=None):
    try:
        info = _table[obj['type']]
    except (TypeError, KeyError):
        info = OBJECT_TEXTS.get(obj.get('type'))
    try:
        info = info['variant'][obj['variant']]
    except (TypeError, KeyError):
        pass
    cnt = obj.get('content')
    if isinstance(cnt, dict) and 'type' in cnt:
        cntinfo = format_text(cnt, info.get('content') if info else None)
        if cntinfo: info = cntinfo
    if not info:
        return
    if 'func' in info:
        res = info['func'](obj)
        if res: info = dict(info, **res)
    for attr in ('prefix', 'text', 'suffix'):
        if attr not in info: continue
        obj[attr] = info[attr]
    return info.get('parent')

# Flatten the textual representation info of obj into a (non-nested) list.
def flatten_text(obj):
    # Traverse input.
    def scrape(obj):
        if obj is None:
            pass
        elif isinstance(obj, str):
            yield obj
        elif isinstance(obj, (tuple, list)):
            for i in obj:
                for j in scrape(i):
                    yield j
        elif isinstance(obj, dict):
            intr = {'type': obj['type']}
            if 'variant' in obj:
                intr['variant'] = obj['variant']
            yield intr
            if 'prefix' in obj:
                for i in scrape(obj['prefix']):
                    yield i
            if 'text' in obj:
                for i in scrape(obj['text']):
                    yield i
            elif 'content' in obj:
                for i in scrape(obj['content']):
                    yield i
            if 'suffix' in obj:
                for i in scrape(obj['suffix']):
                    yield i
            yield {}
        else:
            raise TypeError('Bad input for flatten_text: %r' % (obj,))
    # Turn stacked states into flat state replacements.
    stack, ret = [], []
    for i in scrape(obj):
        if not isinstance(i, dict):
            ret.append(i)
        elif i:
            stack.append(i)
            ret.append(i)
        elif len(stack) > 1:
            stack.pop()
            ret.append(stack[-1])
        else:
            ret.append(i)
    return ret

# Render the textual representation of obj into a single string with embedded
# formatting instructions for term (or none if that is None).
STYLES = {}
def render_text(obj, term=None):
    if term is not None:
        styles = STYLES[term]
    else:
        styles = None
    ret = []
    for i in flatten_text(obj):
        if isinstance(i, str):
            ret.append(i)
        elif term is None:
            pass
        else:
            item = styles.get(i.get('type'))
            if isinstance(item, dict):
                newitem = item.get(i.get('variant'))
                if newitem: item = newitem
            if not item: item = styles[None]
            ret.append(item)
    return ''.join(ret)

# Terminal type registry
TERMTYPES = {}
def termtype(name):
    def callback(cls):
        TERMTYPES[name] = cls
        return cls
    return callback

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
        VARS = {'nick': {'type': str, 'private': False, 'rw': True},
                'term': {'type': str, 'private': True, 'rw': True},
                'send-text': {'type': bool, 'private': True, 'rw': True,
                              'default': True},
                'joined': {'type': bool, 'private': False, 'rw': False,
                           'default': False}}

        def __init__(self, distributor, endpoint):
            self.distributor = distributor
            self.endpoint = endpoint
            self.id = endpoint.id
            self.vars = {k: v['default'] for k, v in self.VARS.items()
                         if 'default' in v}
            self.discipline = DoorstepLineDiscipline(self)
            self._closing = False
            distributor._add_handler(self)

        def deliver(self, message):
            if self.vars['send-text']: format_text(message)
            self.discipline.deliver(message)

        def _user_info(self):
            return {'type': 'user', 'uid': self.id,
                    'content': self.vars['nick']}

        def _process_post(self, msg):
            return {'type': 'post', 'variant': msg['variant'],
                    'sender': self._user_info(), 'timestamp': time.time(),
                    'content': msg['content']}

        def submit(self, message):
            def reply(msg):
                msg['seq'] = message.get('seq')
                self.deliver(msg)
            def broadcast(msg):
                self.distributor.broadcast(msg, {self.id: {'seq':
                    message.get('seq')}})
            if message['type'] == 'ping':
                reply({'type': 'pong'})
            elif message['type'] == 'query':
                reply(self.query_var(message['content']))
            elif message['type'] == 'update':
                res = self.update_var(message['content'])
                desc = self.VARS[res['content']['variant']]
                if res['type'] == 'updated' and not desc['private']:
                    broadcast(res)
                else:
                    reply(res)
            elif message['type'] == 'join':
                res = self.can_join()
                if res:
                    reply(res)
                else:
                    self.vars['joined'] = True
                    broadcast({'type': 'joined',
                               'content': self._user_info()})
            elif message['type'] == 'send':
                broadcast({'type': 'chat',
                           'content': self._process_post(message)})
            elif message['type'] == 'leave':
                res = self.can_leave()
                if res:
                    reply(res)
                else:
                    self.vars['joined'] = False
                    broadcast({'type': 'left', 'variant': 'normal',
                               'content': self._user_info()})
            elif message['type'] == 'quit':
                if self.vars['joined']:
                    self.vars['joined'] = False
                    broadcast({'type': 'left', 'variant': 'normal',
                               'content': self._user_info()})
                self.close()
            else:
                self.distributor.handle(self, message)

        def close(self):
            if not self._closing:
                self._closing = True
                if self.vars['joined']:
                    self.vars['joined'] = False
                    self.distributor.broadcast({'type': 'left',
                        'variant': 'abrupt', 'content': self._user_info()})
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
                desc = self.VARS[variable['variant']]
            except KeyError:
                return make_error('NOVAR', True)
            cltid = variable.get('uid', self.id)
            if cltid != self.id and desc['private']:
                return make_error('VARPRIV', True)
            try:
                hnd = self.distributor.get_handler(cltid)
            except KeyError:
                return make_error('NOCLNT', True)
            try:
                value = hnd.vars[variable['variant']]
            except KeyError:
                return make_error('NOVAL', True)
            return {'type': 'success', 'content': {'type': 'variable',
                'variant': variable['variant'], 'uid': cltid,
                'content': value}}

        def update_var(self, variable):
            try:
                desc = self.VARS[variable['variant']]
            except KeyError:
                return make_error('NOVAR', True)
            cltid = variable.get('uid', self.id)
            if cltid != self.id or not desc['rw']:
                return make_error('VARRO', True)
            try:
                value = desc['type'](variable['content'])
            except ValueError:
                return make_error('BADVAL', True)
            oldvar = {'type': 'variable', 'variant': variable['variant'],
                      'uid': self.id}
            try:
                oldvar['content'] = self.vars[variable['variant']]
            except KeyError:
                pass
            self.vars[variable['variant']] = value
            return {'type': 'updated', 'from': oldvar,
                'content': dict(oldvar, content=value)}

        def can_join(self):
            if self.vars['joined']:
                return make_error('AJOINED', True)
            elif any(k for k in self.VARS if k not in self.vars):
                return make_error('NORDY', True)
            else:
                return None

        def can_leave(self):
            if not self.vars['joined']:
                return make_error('ALEFT', True)
            else:
                return None

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

    def handle(self, handler, message):
        def reply(msg):
            msg['seq'] = message.get('seq')
            handler.deliver(msg)
        reply(make_error('NOTYPE', True))

    def broadcast(self, message, amend=None):
        if amend is None: amend = {}
        with self.lock:
            hnds = tuple(self.handlers.values())
        for h in hnds:
            if h.id in amend:
                h.deliver(dict(message, **amend[h.id]))
            else:
                h.deliver(message)
    def sysmsg(self, text):
        self.broadcast({'type': 'sysmsg', 'text': 'Server will shut down now.'})

    def close(self):
        self.sysmsg('Server will shut down now.')
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
            try:
                self.handler.endpoint.file.write(data)
                self.handler.endpoint.file.flush()
            except IOError as e:
                if e.errno == errno.EPIPE: return
                raise
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

# Intermediate class implementing in-chat commands.
class CommandLineDiscipline(LineDiscipline):
    HELP = (('help', '[command]', 'Display help.', '', 'DJ'),
            ('ping', '', 'Check connectivity.', '', 'DJ'),
            ('term', '[dumb|ansi]', 'Query/Set terminal type.',
                 'dumb -- Minimalistic mode.\n'
                 'ansi -- Advanced escape sequences.', 'D'),
            ('nick', '[name]', 'Query/Set nickname.', '', 'DJ'),
            ('join', '', 'Join chat', '', 'DJ'),
            ('say', '<message>', 'Post a message.',
                 '...If the message starts with a slash.', 'J'),
            ('me', '<message>', 'Post an emote message.', '', 'J'),
            ('leave', '', 'Leave chat', '', 'J'),
            ('quit', '', 'Terminate connection.', '', 'DJ'))

    @classmethod
    def format_help(cls, cmd=None, cmdcls=None, long=False):
        sp = lambda s, x: s + x if x else ''
        rf = lambda x: '# ' + x.replace('\n', '\n# ')
        # Filter commands.
        cmds = cls.HELP
        if cmd is not None:
            cmds = [i for i in cmds if i[0] == cmd]
        if cmdcls:
            cmds = [i for i in cmds if cmdcls in i[4]]
        # Format output.
        if len(cmds) == 0:
            return ''
        elif len(cmds) == 1:
            n, a, o, d, c = cmds[0]
            suff = sp(' -- ', o) + sp('\n', d) if long else ''
            return '# USAGE: /%s%s%s' % (n, sp(' ', a), suff)
        else:
            ret = ['# HELP\n']
            for n, a, o, d, c in cmds:
                ret.extend(('# /', n, sp(' ', a), sp(' -- ', o), '\n'))
                if long and d: ret.append(rf(d))
            return ''.join(ret).rstrip('\n')

    def __init__(self, handler):
        LineDiscipline.__init__(self, handler)
        self.helpclass = None
        self.seq = 0
        self.lock = threading.RLock()

    def _submit(self, packet):
        with self.lock:
            self.seq -= 1
            packet['seq'] = self.seq
            self.submit(packet)
            return self.seq

    def handle_cmdline(self, line):
        def usage():
            return 'FAIL ' + self.format_help(tokens[0][1:], self.helpclass)
        def packet(_type, **content):
            return {'type': _type, 'content': content}
        tokens = Token.extract(line)
        if not tokens:
            return None
        elif tokens[0] == '/help':
            if len(tokens) == 1:
                return 'OK ' + self.format_help(None, self.helpclass)
            elif len(tokens) == 2:
                cmd = tokens[1]
                if cmd.startswith('/'): cmd = cmd[1:]
                desc = self.format_help(cmd, self.helpclass, True)
                if not desc: return 'FAIL # Unknown command /%s.' % cmd
                return 'OK ' + desc
            else:
                return usage()
        elif tokens[0] == '/ping':
            if len(tokens) != 1: return usage()
            return packet('ping')
        elif tokens[0] == '/term':
            if len(tokens) == 1:
                return packet('query', type='variable', variant='term')
            elif len(tokens) == 2:
                if tokens[1] in TERMTYPES:
                    return packet('update', type='variable', variant='term',
                                  content=tokens[1])
                else:
                    return 'FAIL # Unknown terminal type: %s.' % tokens[1]
            else:
                return usage()
        elif tokens[0] == '/nick':
            if len(tokens) == 1:
                return packet('query', type='variable', variant='nick')
            elif len(tokens) == 2:
                return packet('update', type='variable', variant='nick',
                              content=tokens[1])
            else:
                return usage()
        elif tokens[0] == '/join':
            if len(tokens) != 1: return usage()
            res = self.handler.can_join()
            if res: return render_text(res)
            return packet('join')
        elif tokens[0] == '/say':
            if len(tokens) == 1:
                rest = ''
            else:
                rest = line[tokens[1].offset:].strip()
            return {'type': 'send', 'variant': 'normal', 'content': rest}
        elif tokens[0] == '/me':
            if len(tokens) == 1:
                rest = ''
            else:
                rest = line[tokens[1].offset:].strip()
            return {'type': 'send', 'variant': 'emote', 'content': rest}
        elif tokens[0] == '/leave':
            if len(tokens) != 1: return usage()
            res = self.handler.can_leave()
            if res: return render_text(res)
            return packet('leave')
        elif tokens[0] == '/quit':
            if len(tokens) != 1: return usage()
            return packet('quit')
        elif tokens[0].startswith('/'):
            return 'FAIL # Unknown command: %s.' % tokens[0]
        else:
            rest = line.strip()
            return {'type': 'send', 'variant': 'normal', 'content': rest}

# Doorstep mode.
# The initial mode a connection is in; a lowest-denominator compromise
# between all clients.
class DoorstepLineDiscipline(CommandLineDiscipline):
    def __init__(self, handler):
        CommandLineDiscipline.__init__(self, handler)
        self.helpclass = 'D'
        self.encoding = 'ascii'
        self.errors = 'replace'

    def init(self, first):
        if first: self.println(APPNAME, 'v' + VERSION)
        self.println(GREETING % VERSION)

    def deliver(self, message):
        if message['type'] == 'sysmsg':
            self.println('#', '!!!', message['text'])
        elif message.get('seq') is None:
            return # Explicitly silenced.
        elif message['type'] == 'updated':
            self.println('OK')
        elif (message['type'] == 'success' and
                message['content']['type'] == 'variable'):
            self.println('OK', '#', render_text(message['content']))
        elif message['type'] == 'failure':
            self.println('FAIL', '#', render_text(message['content']))

    def __call__(self):
        while 1:
            line = self.readline()
            if not line: return None
            res = self.handle_cmdline(line)
            if res is None:
                continue
            elif isinstance(res, str):
                self.println(res)
            elif res['type'] == 'join':
                try:
                    term = self.handler.vars['term']
                    return TERMTYPES[term](self.handler)
                except KeyError:
                    self.println('FAIL', '#', 'Internal error?!')
            else:
                self._submit(res)

# Dumb mode.
# For the poor people who are left without anything.
@termtype('dumb')
class DumbLineDiscipline(CommandLineDiscipline):
    def __init__(self, endpoint):
        CommandLineDiscipline.__init__(self, endpoint)
        self.encoding = 'ascii'
        self.errors = 'replace'
        self.pending = queue.Queue()
        self.busy = False
        self.newline = False

    def init(self, first):
        self._println('# Press Return to write a message.')
        self._submit({'type': 'join'})

    def _println(self, *args):
        with self.lock:
            nl = self.newline
            self.newline = True
        if not nl:
            self.println(*args, end='')
        elif not args:
            self.println('\n', end='')
        else:
            self.println('\n' + args[0], *args[1:], end='')

    def _deliver(self, message):
        text = render_text(message)
        if not text: return
        self._println(text)

    def deliver(self, message):
        if (message['type'] == 'chat' and
                message['content']['sender']['uid'] == self.handler.id):
            return # Own chat messages already printed.
        with self.lock:
            if self.busy:
                self.pending.put(message)
            else:
                self._deliver(message)

    def quit(self, last):
        with self.lock:
            nl = self.newline
            self.newline = False
        text = ('\n' if nl else '') + '# Bye!'
        self.println(text)

    def __call__(self):
        def deliver():
            while 1:
                try:
                    self._deliver(self.pending.get(False))
                except queue.Empty:
                    break
        while 1:
            deliver()
            line = self.readline()
            if not line:
                deliver()
                return None
            self.newline = False
            res = self.handle_cmdline(line)
            if res is None:
                pass
            elif isinstance(res, str):
                self._println(res)
            else:
                self._submit(res)
                if res['type'] == 'leave':
                    deliver()
                    return DoorstepLineDiscipline(self.handler)
            deliver()
            with self.lock:
                self.busy ^= True
                if self.busy:
                    self._println('<' + self.handler.vars['nick'] + '> ')

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

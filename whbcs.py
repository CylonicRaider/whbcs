#!/usr/bin/env python3
# -*- coding: ascii -*-

# Weird HomeBrew Chat Server

APPNAME = 'WHBCS'
VERSION = '2.0'

import sys, os, re, time, socket
import json
import threading
import errno, signal
import logging

try:
    import Queue as queue
except ImportError:
    import queue

try:
    unicode
except NameError:
    unicode = str
try:
    basestring
except NameError:
    basestring = (str, unicode)

HOST = ''
PORT = 4321
REUSE_ADDR = True
KEEP_ALIVE = True
BEACONS = False

GREETING = '''
# Weird HomeBrew Chat Server v%s
# Type "/help" for a command overview.
'''[1:-1] % VERSION

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
class Token(unicode):
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
        inst = unicode.__new__(cls, obj)
        inst.offset = offset
        return inst

    def __repr__(self):
        return '%s(%s, %r)' % (self.__class__.__name__,
            unicode.__repr__(self), self.offset)

# Error registry.
ERRORS = {
    'AJOINED': 'Already joined.',
    'ALEFT': 'Already left.',
    'BADENC': 'Bad encoding.',
    'BADLINE': 'Bad line.',
    'BADOBJ': 'Bad object.',
    'BADVAL': 'Bad value.',
    'INTER': 'Internal error?!',
    'NOCLNT': 'No such client.',
    'NOJOIN': 'Not joined.',
    'NORDY': 'Not ready.',
    'NOTYPE': 'No such message type.',
    'NOVAL': 'Variable has no value.',
    'NOVAR': 'No such variable.',
    'VARJRO': 'Variable is read-only while joined.',
    'VARPRIV': 'Variable is private.',
    'VARRO': 'Variable is read-only.',
    }
def make_error(code, wrap=False):
    err = {'type': 'error', 'code': code, 'content': ERRORS[code]}
    return {'type': 'failure', 'content': err} if wrap else err

# Text member generation.
def _mkhl(v, t): return {'type': 'hl', 'variant': v, 'text': t}
_star = _mkhl('msgpad', '*')
_sstar, _stars = _mkhl('syspad', '*'), _mkhl('syspad', '***')
def _format_ok(obj):
    if obj.get('content'):
        return {'prefix': (_mkhl('reply', 'OK'), ' ', _mkhl('replypad', '#'),
                           ' ')}
    else:
        return {'text': _mkhl('reply', 'OK')}
def _format_updated(obj):
    if obj['content']['variant'] == 'nick' and 'content' in obj['from']:
        fromment = {'type': 'mention', 'content': obj['from']['content'],
                    'uid': obj['from']['uid']}
        tousr = {'type': 'user', 'content': obj['content']['content'],
                 'uid': obj['content']['uid']}
        format_text(fromment)
        format_text(tousr)
        return {'prefix': (_sstar, ' '), 'text': _mkhl('msgtext',
              (fromment, ' is now ', tousr))}
    else:
        return {'text': None}
def _format_post(obj):
    format_text(obj['sender'])
    if obj['variant'] == 'emote':
        return {'prefix': (_star, ' ', obj['sender'], ' ')}
    else:
        return {'prefix': (_mkhl('chatpad', '<'), obj['sender'],
                           _mkhl('chatpad', '>'), ' ')}
def _format_listing(obj):
    items = []
    for n, i in enumerate(obj['content']):
        format_text(i)
        if n: items.append(',')
        items.append(dict(i, type='mention'))
    if not items: items.append('-none-')
    return {'prefix': 'Users online: ', 'text': items}
OBJECT_TEXTS = {
    'pong': {'prefix': _mkhl('reply', 'PONG')},
    'success': {'func': _format_ok},
    'failure': {'prefix': (_mkhl('reply', 'FAIL'), ' ',
                           _mkhl('replypad', '#'), ' ')},
    'updated': {'func': _format_updated},
    'joined': {
        'prefix': (_sstar, ' '),
        'suffix': (' ', _mkhl('msgtext', 'has joined'))
    },
    'left': {
        'prefix': (_sstar, ' '),
        'suffix': (' ', _mkhl('msgtext', 'has left')),
        'variant': {
            'abrupt': {
                'prefix': (_sstar, ' '),
                'suffix': (' ', _mkhl('msgerr', 'has left unexpectedly'))
            }
        }
    },
    'sysmsg': {'prefix': (_stars, ' ')},
    'post': {'func': _format_post},
    'listing': {'func': _format_listing}}
# Operates in-place.
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
        elif isinstance(obj, basestring):
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
            if ret and isinstance(ret[-1], dict): ret.pop()
            ret.append(i)
        elif ret[-1] is stack[-1]:
            stack.pop()
            ret.pop()
        else:
            stack.pop()
            if isinstance(ret[-1], dict): ret.pop()
            # Copy to prevent triggering the empty group collapsing code.
            ret.append(dict(stack[-1]) if stack else i)
    if stack: ret.append({})
    return ret

# Render the textual representation of obj into a single string with embedded
# formatting instructions for term (or none if that is None).
_aclr = lambda *c: '\033[' + ';'.join(map(str, c)) + 'm'
STYLES = {'ansi': {
        None: _aclr(0),
        'error': _aclr(22, 31),
        'user': _aclr(22, 35),
        'mention': _aclr(22, 33),
        'hl': {
            None: _aclr(0),
            'reply': _aclr(39, 1),
            'replypad': _aclr(0),
            'syspad': _aclr(39, 1),
            'sysmsg': _aclr(0),
            'msgpad': _aclr(22, 36),
            'msgtext': _aclr(22, 32),
            'msgerr': _aclr(22, 31),
            'chatpad': _aclr(22, 36)
        },
        'char': _aclr(39, 1)
    }}
def render_text(obj, term=None):
    styles = None if term is None else STYLES[term]
    ret = []
    for i in flatten_text(obj):
        if isinstance(i, basestring):
            ret.append(i)
        elif styles:
            item = styles.get(i.get('type'))
            if isinstance(item, dict):
                item = item.get(i.get('variant'))
            if not item: item = styles[None]
            ret.append(item)
    return ''.join(ret)

# Validate that a dict conforms to the given format.
class Validator:
    @staticmethod
    def forPattern(tp):
        if isinstance(tp, Validator):
            return tp
        elif isinstance(tp, dict):
            return DictValidator(**tp)
        elif isinstance(tp, tuple):
            return ValueValidator(*tp)
        elif isinstance(tp, type):
            return Validator(tp)
        else:
            return ValueValidator(tp)
    def __init__(self, type):
        self.type = type
    def __call__(self, obj):
        return isinstance(obj, self.type)

class ValueValidator(Validator):
    def __init__(self, *values):
        Validator.__init__(self, object)
        self.values = values
    def __call__(self, obj):
        return (obj in self.values)

class DictValidator(Validator):
    def __init__(_self, _optional=(), **_kwds):
        Validator.__init__(_self, dict)
        _self.optional = _optional
        _self.members = {}
        for k, v in _kwds.items():
            _self.members[k] = Validator.forPattern(v)
    def __call__(self, obj):
        if not isinstance(obj, dict): return False
        for k, v in self.members.items():
            if k not in obj:
                if k in self.optional: continue
                return False
            if not v(obj[k]): return False
        if set(obj).difference(self.members): return False
        return True

_DV = DictValidator
VALIDATORS = {
    'ping': _DV(type='ping'),
    'query': _DV(type='query', content=_DV(('uid',), type='variable',
        variant=str, uid=int)),
    'update': _DV(type='update', content=_DV(type='variable',
        variant=str, content=object)),
    'join': _DV(type='join'),
    'leave': _DV(type='leave'),
    'list': _DV(type='list'),
    'send': _DV(type='send', variant=('normal', 'emote'), content=str),
    'quit': _DV(type='quit')
    }
def validate_input(obj):
    if not isinstance(obj, dict) or 'type' not in obj:
        return False
    return VALIDATORS[obj['type']](obj)

# Parse the content of a post object.
MENTION_RE = re.compile(r'\B@([^\s\0-\x1f]+?)(?=[.,:;!?)]*(\s|$))')
INTERESTING_RE = re.compile(MENTION_RE.pattern + r'|[\0-\x1f\x7f]')
def parse_message(content):
    ret, pos = [], 0
    while 1:
        m = INTERESTING_RE.search(content, pos)
        if not m:
            break
        if m.start() != pos:
            ret.append(content[pos:m.start()])
        if m.group().startswith('@'):
            ret.append({'type': 'mention', 'content': m.group(1),
                        'prefix': '@'})
        elif m.group() == '\x7f':
            ret.append({'type': 'char', 'content': m.group(), 'text': '^?'})
        else:
            ret.append({'type': 'char', 'content': m.group(),
                        'text': '^' + chr(ord(m.group()) + 0x40)})
        pos = m.end()
    if pos != len(content): ret.append(content[pos:])
    return ret

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

        def log(self, *args):
            self.server.log(*args)

        def close(self):
            self.log('CLOSING id=%r' % self.id)
            silence(self.socket.shutdown, socket.SHUT_RD)
            silence(self.file.flush)
            silence(self.socket.shutdown, socket.SHUT_WR)
            silence(self.socket.close)

        def __call__(self):
            self.handler()

    @classmethod
    def listen(cls, addr, logger=None, beacons=False, reuse_addr=False,
               keep_alive=False):
        if logger:
            logger.info('LISTENING bind=%r' % (addr,))
        s = socket.socket()
        if reuse_addr:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if keep_alive:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        s.bind(addr)
        s.listen(5)
        return cls(s, logger, beacons)

    def __init__(self, socket, logger=None, beacons=False):
        self.socket = socket
        self.logger = logger
        self.beacons = beacons
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
        if self.beacons:
            spawn_thread(self.distributor._beacons)
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
        VARS = {'nick': {'type': str, 'private': False, 'rw': True,
                         'check': re.compile(r'[^\s\0-\x1f]+$').match},
                'term': {'type': str, 'private': True, 'rw': True,
                         'doorstep': True},
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

        def log(self, *args):
            self.endpoint.log(*args)

        def deliver(self, message):
            if self.vars['send-text']: format_text(message)
            self.discipline.deliver(message)

        def _user_info(self):
            return {'type': 'user', 'uid': self.id,
                    'content': self.vars['nick']}

        def _process_post(self, msg):
            return {'type': 'post', 'variant': msg['variant'],
                    'sender': self._user_info(), 'timestamp': time.time(),
                    'content': msg['content'],
                    'text': parse_message(msg['content'])}

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
                if res['type'] == 'updated':
                    desc = self.VARS[res['content']['variant']]
                    if not desc['private'] and self.vars['joined']:
                        if res['content']['variant'] == 'nick':
                            self.log('RENAME id=%r from=%r to=%r' % (self.id,
                                res['from']['content'],
                                res['content']['content']))
                        broadcast(res)
                    else:
                        reply(res)
                else:
                    reply(res)
            elif message['type'] == 'join':
                res = self.can_join()
                if res:
                    reply(res)
                else:
                    self.log('JOIN id=%r term=%r nick=%r' % (self.id,
                        self.vars['term'], self.vars['nick']))
                    self.vars['joined'] = True
                    broadcast({'type': 'joined',
                               'content': self._user_info()})
            elif message['type'] == 'list':
                reply({'type': 'success', 'content': {'type': 'listing',
                    'content': self.distributor._make_listing()}})
            elif message['type'] == 'send':
                if self.vars['joined']:
                    self.log('%s id=%r nick=%r text=%r' % (
                        'EMOTE' if message['variant'] == 'emote' else 'SAY',
                        self.id, self.vars['nick'], message['content']))
                    broadcast({'type': 'chat',
                               'content': self._process_post(message)})
                else:
                    reply(make_error('NOJOIN', True))
            elif message['type'] == 'leave':
                res = self.can_leave()
                if res:
                    reply(res)
                else:
                    self.log('LEAVE id=%r' % self.id)
                    self.vars['joined'] = False
                    broadcast({'type': 'left', 'variant': 'normal',
                               'content': self._user_info()})
            elif message['type'] == 'quit':
                if self.vars['joined']:
                    self.vars['joined'] = False
                    broadcast({'type': 'left', 'variant': 'normal',
                               'content': self._user_info()})
                self.close(True)
            else:
                self.distributor.handle(self, message)

        def close(self, ok=False):
            if not self._closing:
                if not ok:
                    self.endpoint.server.log('ABORTED id=%r' % self.id)
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
            if desc.get('doorstep') and self.vars['joined']:
                return make_error('VARJRO', True)
            try:
                value = desc['type'](variable['content'])
                if 'check' in desc and not desc['check'](value):
                    raise ValueError('Variable does not pass validation.')
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

        def visible(self):
            return self.vars['joined']

    def __init__(self, server):
        self.server = server
        self.handlers = {}
        self.lock = threading.RLock()

    def _beacons(self):
        while 1:
            time.sleep(30)
            self.broadcast({'type': 'beacon', 'timestamp': time.time()})

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

    def _make_listing(self):
        with self.lock:
            handlers = [h for h in self.handlers.values() if h.visible()]
        return [h._user_info() for h in handlers]

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

# Line discipline allowing (more) direct access to the API.
class APILineDiscipline(LineDiscipline):
    def __init__(self, handler):
        LineDiscipline.__init__(self, handler)
        self.encoding = 'ascii'
        self.errors = 'strict'

    def _deliver(self, message):
        if self.handler.vars['send-text']:
            format_text(message)
        self.deliver(message)

    def deliver(self, message):
        self.write(json.dumps(message, separators=(',', ':')) + '\n')

    def __call__(self):
        while 1:
            try:
                line = self.readline()
            except UnicodeDecodeError:
                self._deliver(make_error('BADENC', True))
                continue
            if not line: return None
            line = line.strip()
            if not line:
                continue
            elif not line.startswith('{'):
                self._deliver(make_error('BADLINE', True))
                continue
            try:
                data = json.loads(line)
            except ValueError:
                self._deliver(make_error('BADLINE', True))
                continue
            if not validate_input(data):
                self._deliver(make_error('BADOBJ', True))
                continue
            if (data['type'] == 'update' and
                    data['content']['variant'] == 'term'):
                self._deliver(make_error('VARRO', True))
                continue
            self.submit(data)

# Intermediate class implementing in-chat commands.
class CommandLineDiscipline(LineDiscipline):
    HELP = (('help', '[command]', 'Display help.', '', 'DJ'),
            ('ping', '', 'Check connectivity.', '', 'DJ'),
            ('term', '[dumb|ansi|vte]', 'Query/Set terminal type.',
                 'dumb -- Minimalistic mode.\n'
                 'ansi -- Advanced escape sequences.\n'
                 'vte -- Workarounds for some buggy terminals.', 'D'),
            ('nick', '[name]', 'Query/Set nickname.', '', 'DJ'),
            ('join', '', 'Join chat', '', 'D'),
            ('list', '', 'List currently present users.', '', 'J'),
            ('say', '<message>', 'Post a message.',
                 '...If the message starts with a slash.', 'J'),
            ('me', '<message>', 'Post an emote message.', '', 'J'),
            ('alert', '[no|ping|once|yes]', 'Query/Set alert mode.',
                 'no -- No alerts at all.\n'
                 'ping -- When @-mentioned.\n'
                 'once -- At the next message, then not.\n'
                 'yes -- At any message\n'
                 'NOTE: Is reset when joining/leaving.', 'J'),
            ('leave', '', 'Leave chat', '', 'J'),
            ('quit', '', 'Terminate connection.', '', 'DJ'))
    REPLIES = ('pong', 'success', 'failure')

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
        self.alerts = 'no'

    def _submit(self, packet):
        with self.lock:
            self.seq -= 1
            packet['seq'] = self.seq
            self.submit(packet)
            return self.seq

    def check_mentions(self, post):
        comp = self.handler.vars['nick'].lower()
        for i in post['text']:
            if (isinstance(i, dict) and i['type'] == 'mention' and
                    i['content'].lower() == comp):
                return True
        return False
    def check_alerts(self, post):
        if self.alerts == 'no':
            return False
        elif self.alerts == 'yes':
            return True
        elif self.alerts == 'once':
            self.alerts = 'no'
            return True
        else:
            res = self.check_mentions(post)
            return res

    def handle_cmdline(self, line):
        def ok(message=None):
            if message is None: return {'type': 'success'}
            return {'type': 'success', 'content': message}
        def fail(message):
            return {'type': 'failure', 'content': {'type': 'error',
                                                   'content': message}}
        def unhash(s):
            return s[2:] if s.startswith('# ') else s
        def usage():
            return fail(unhash(self.format_help(tokens[0][1:],
                                                self.helpclass)))
        def packet(_type, **_content):
            return {'type': _type, 'content': _content}
        tokens = Token.extract(line)
        if not tokens:
            return None
        elif tokens[0] == '/help':
            if len(tokens) == 1:
                return ok(unhash(self.format_help(None, self.helpclass)))
            elif len(tokens) == 2:
                cmd = tokens[1]
                if cmd.startswith('/'): cmd = cmd[1:]
                desc = self.format_help(cmd, self.helpclass, True)
                if not desc: return fail('Unknown command /%s.' % cmd)
                return ok(unhash(desc))
            else:
                return usage()
        elif tokens[0] == '/ping':
            if len(tokens) == 1:
                return {'type': 'pong'}
            else:
                return usage()
        elif tokens[0] == '/term':
            if len(tokens) == 1:
                return packet('query', type='variable', variant='term')
            elif len(tokens) == 2:
                if tokens[1] in TERMTYPES:
                    return packet('update', type='variable', variant='term',
                                  content=tokens[1])
                else:
                    return fail('Unknown terminal type: %s.' % tokens[1])
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
            if res: return res
            return packet('join')
        elif tokens[0] == '/list':
            if len(tokens) != 1: return usage()
            return packet('list')
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
        elif tokens[0] == '/alert':
            if len(tokens) == 1:
                return ok(self.alerts)
            elif len(tokens) == 2:
                if tokens[1] in ('no', 'ping', 'once', 'yes'):
                    self.alerts = str(tokens[1])
                    return ok()
                else:
                    return fail('Unknown alert mode: %s.' % tokens[1])
            else:
                return usage()
        elif tokens[0] == '/leave':
            if len(tokens) != 1: return usage()
            res = self.handler.can_leave()
            if res: return res
            return packet('leave')
        elif tokens[0] == '/quit':
            if len(tokens) != 1: return usage()
            return packet('quit')
        elif tokens[0].startswith('/'):
            return fail('Unknown command: %s.' % tokens[0])
        else:
            rest = line.strip()
            return {'type': 'send', 'variant': 'normal', 'content': rest}

# Doorstep mode.
# The initial mode a connection is in; a lowest-denominator compromise
# between all clients.
class DoorstepLineDiscipline(CommandLineDiscipline):
    def __init__(self, handler):
        CommandLineDiscipline.__init__(self, handler)
        self.encoding = 'ascii'
        self.errors = 'replace'
        self.helpclass = 'D'

    def init(self, first):
        if first:
            self.println(APPNAME, 'v' + VERSION)
            self.println(GREETING)

    def deliver(self, message):
        if message['type'] == 'sysmsg':
            self.println('#', '!!!', message['text'])
        elif message['type'] == 'beacon':
            self.write('\0')
        elif 'seq' not in message:
            return # Explicitly silenced.
        elif message['type'] == 'updated':
            self.println('OK')
        elif message['type'] == 'pong':
            self.println('PONG')
        elif message['type'] == 'success':
            if 'content' not in message:
                self.println('OK')
            elif isinstance(message['content'], basestring):
                self.println('OK', '#', message['content'])
            elif message['content']['type'] == 'variable':
                self.println('OK', '#', render_text(message['content']))
        elif message['type'] == 'failure':
            self.println('FAIL', '#', render_text(message['content']))

    def __call__(self):
        while 1:
            line = self.readline()
            if not line: return None
            if re.match(r'\s*/api(\s|$)', line):
                tokens = Token.extract(line)
                if len(tokens) != 1:
                    self.println('FAIL', '#', '/api takes no arguments')
                    continue
                self.println('OK')
                self.handler.vars['term'] = 'api'
                return APILineDiscipline(self.handler)
            res = self.handle_cmdline(line)
            if res is None:
                continue
            elif res['type'] in self.REPLIES:
                res['seq'] = None
                format_text(res)
                self.deliver(res)
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
        self.helpclass = 'J'
        self.pending = queue.Queue()
        self.busy = False
        self.newline = False

    def init(self, first):
        self._println('# Press Return to write a message.')
        self._submit({'type': 'join'})
        self._println('# Listing users...')
        self._submit({'type': 'list'})

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
        if (message['type'] == 'chat' and
                self.check_alerts(message['content'])):
            text += '\a'
        self._println(text)
    def _deliver_all(self):
        while 1:
            try:
                self._deliver(self.pending.get(False))
            except queue.Empty:
                break

    def deliver(self, message):
        if (message['type'] == 'chat' and
                message['content']['sender']['uid'] == self.handler.id):
            return # Own chat messages already typed by user.
        elif message['type'] == 'beacon':
            self.write('\0') # Beacons are delivered unconditionally.
        with self.lock:
            if self.busy:
                self.pending.put(message)
            else:
                self._deliver(message)

    def quit(self, last):
        self._deliver_all()
        with self.lock:
            nl = self.newline
            self.newline = False
        text = ('\n' if nl else '') + '# Bye!'
        self.println(text)

    def __call__(self):
        self._deliver_all()
        while 1:
            line = self.readline()
            if not line: return None
            self.newline = False
            res = self.handle_cmdline(line)
            if res is None:
                pass
            elif res['type'] in self.REPLIES:
                format_text(res)
                self.deliver(res)
            else:
                self._submit(res)
                if res['type'] == 'leave':
                    self._deliver_all()
                    return DoorstepLineDiscipline(self.handler)
            self._deliver_all()
            with self.lock:
                self.busy ^= True
                if self.busy:
                    self._println('<' + self.handler.vars['nick'] + '> ')

# ANSI terminal mode.
# Well, kind of.
@termtype('ansi')
class ANSILineDiscipline(CommandLineDiscipline):
    @staticmethod
    def calibrate_height(write, readline):
        write('\033[r\033[H\033[2J')
        write('# Some text should appear at the bottom of the screen.\n'
              '# Press Return (repeatedly) if it does, or type "cancel"\n'
              '# (and press Return) if not.\n')
        ly = None
        while 1:
            write('\033[100B\033[6n')
            reply, state, nbuf = readline(), 0, ''
            # Since any letter of "cancel" is invalid in any state, it is
            # handled explicitly.
            for ch in reply:
                if state == 0:
                    if ch != '\033': return None
                    state = 1
                elif state == 1:
                    if ch != '[': return None
                    state = 2
                elif state == 2:
                    if ch in '0123456789':
                        nbuf += ch
                    elif ch == ';':
                        state = 3
                    else:
                        return None
                elif state == 3:
                    if ch == '\n':
                        break
                    elif ch.isspace():
                        pass
                    elif ch not in '0123456789;R':
                        return None
            else:
                return None
            if not nbuf: return None
            y = int(nbuf, 10)
            if y == ly:
                return y
            else:
                ly = y

    @staticmethod
    def make_prompt(user):
        return render_text([_mkhl('chatpad', '<'), user,
                            _mkhl('chatpad', '>'), ' '], 'ansi')

    def __init__(self, endpoint):
        CommandLineDiscipline.__init__(self, endpoint)
        self.encoding = 'ascii'
        self.errors = 'replace'
        self.helpclass = 'J'
        self.height = None

    def init(self, first):
        self.println('# Calibrating terminal...')
        self.height = self.calibrate_height(self.write, self.readline)
        if self.height is None:
            self.println('# Calibration failed; reverting to dumb mode.')
            return
        self.println('\033[2J\033[1;%sr\033[%s;1H' % (self.height - 1,
                                                      self.height))
        self._submit({'type': 'join'})
        self._println('# Listing users...')
        self._submit({'type': 'list'})

    def _println(self, *args):
        self.write('\0337\033[A\n' + ' '.join(args) + '\0338')

    def deliver(self, message):
        if message['type'] == 'beacon':
            self.write('\0')
            return
        text = render_text(message, 'ansi')
        if not text: return
        if (message['type'] == 'chat' and
                self.check_alerts(message['content'])):
            text += '\a'
        self._println(text)

    def quit(self, last):
        self.println('\033c# Bye!')

    def _write_prompt(self, echo=None):
        prompt = self.make_prompt(self.handler._user_info())
        if echo is None:
            self.write('\033[K' + prompt)
        elif echo.startswith('/'):
            if (re.match(r'/me\b', echo) or
                    re.match(r'/nick\s+\S+$', echo)):
                return
            self._println(prompt + echo)

    def __call__(self):
        if self.height is None: return DumbLineDiscipline(self.handler)
        while 1:
            self._write_prompt()
            line = self.readline()
            if not line: break
            self._write_prompt(line.strip())
            res = self.handle_cmdline(line)
            if res is None:
                pass
            elif res['type'] in self.REPLIES:
                format_text(res)
                self.deliver(res)
            else:
                self._submit(res)
                if res['type'] == 'leave':
                    return DoorstepLineDiscipline(self.handler)

# libvte line discipline.
# Includes workarounds for some of its bugs.
@termtype('vte')
class VTELineDiscipline(ANSILineDiscipline):
    def _println(self, *args):
        # Cursor placement works differently; positioning explicitly.
        self.write('\0337\033[%s;1H\n%s\0338' % (self.height - 1,
                                                 ' '.join(args)))

    def deliver(self, message):
        # Own messages already pushed up by bugs.
        if (message['type'] == 'chat' and
                message['content']['sender']['uid'] == self.handler.id):
            return
        ANSILineDiscipline.deliver(self, message)

    def _write_prompt(self, echo=None):
        prompt = self.make_prompt(self.handler._user_info())
        if echo is None:
            self.write('\033[K' + prompt)
            return
        # Commands already pushed up by bugs.

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
    host, port, reuse_addr, keep_alive = HOST, PORT, REUSE_ADDR, KEEP_ALIVE
    beacons, logfile = BEACONS, None
    try:
        it = iter(sys.argv[1:])
        for arg in it:
            if arg == '--help':
                die('USAGE: %s [--help] [--host host] [--port port] '
                    '[--[no-]reuseaddr] [--[no-]keepalive] [--[no-]beacons] '
                    '[--logfile logfile]\n'
                    'Defaults: --host %r --port %s --%sreuseaddr '
                    '--%skeepalive --%sbeacons\n' % (sys.argv[0], HOST, PORT,
                    '' if REUSE_ADDR else 'no-', '' if KEEP_ALIVE else 'no-',
                    '' if BEACONS else 'no-'), 0)
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
            elif arg == '--keepalive':
                keep_alive = True
            elif arg == '--no-keepalive':
                keep_alive = False
            elif arg == '--beacons':
                beacons = True
            elif arg == '--no-beacons':
                beacons = False
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
    s = Server.listen((host, port), logging.getLogger(), beacons, reuse_addr,
                      keep_alive)
    try:
        s()
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

if __name__ == '__main__': main()

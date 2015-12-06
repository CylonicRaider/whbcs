#!/usr/bin/env python3
# -*- coding: ascii -*-

# Weird HomeBrew Chat Server -- v1.2.

from __future__ import print_function

import sys
import re
import time
import io
import socket
import logging
import threading
import signal

try:
    from Queue import Queue, Empty
except ImportError:
    from queue import Queue, Empty

SIGNATURE = 'WHBCS v1.3'
COMMENT = '''
# Weird Homebrew Chat Server (v1.3).
# Type "/help" for a command overview.
'''[1:-1]
HELP = '''
# HELP
# Configuration:
#   /term [dumb|ansi|vte] -> Query/Set terminal type.
#     dumb: minimalistic mode; ansi: advanced escape sequences;
#     vte: workaround for some buggy terminals.
#   /nick [<nick>] -> Query/Set nick-name.
#   /alert [off|once|mention|on] -> Query/Set alert status.
#     off: disabled at all; once; alert only once; mention:
#     alert for any @-mention of myself; on: alert for any.
#   /ao -> Alias for /alert once.
# Connection control:
#   /join -> Join room.
#   /leave -> Leave room.
#   /quit -> Quit (close connection).
# Chatting
#   /say <text...> -> Say a message (explicitly).
#   /me <text...> -> Emote message.
#   /list -> List users online.
# Other
#   /ping -> Send a PONG reply.
'''[1:-1]

HOST = ''
PORT = 4321

def spawn_thread(func, *args, **kwds):
    thr = threading.Thread(target=func, args=args, kwargs=kwds)
    thr.setDaemon(True)
    thr.start()
    return thr

def format_print(*args, **kwds):
    return (kwds.get('sep', ' ').join(map(kwds.get('tr', str), args)) +
            kwds.get('end', '\n'))

COLOR_MAP = {'none'       : (    0,), 'bold'     : (0,  1 ),
             'black'      : (30, 22), 'red'      : (31, 22),
             'green'      : (32, 22), 'orange'   : (33, 22),
             'blue'       : (34, 22), 'purple'   : (35, 22),
             'turquiose'  : (36, 22), 'gray'     : (37, 22),
             'darkgray'   : (30, 1 ), 'brightred': (31, 1 ),
             'brightgreen': (32, 1 ), 'yellow'   : (33, 1 ),
             'brightblue' : (34, 1 ), 'magenta'  : (35, 1 ),
             'cyan'       : (36, 1 ), 'white'    : (37, 1 )}
def format_message(msg, color=False):
    def split(msg, cc=(0,)):
        parts = []
        if isinstance(msg, (str, dict)):
            it = iter((msg,))
        else:
            it = iter(msg)
        for e in it:
            if isinstance(e, dict):
                clr = e.get('color')
                if isinstance(clr, str):
                    parts.extend(COLOR_MAP[clr])
                elif isinstance(clr, (list, tuple)):
                    parts.extend(clr)
                elif isinstance(clr, int):
                    parts.append(clr)
                else:
                    clr = cc
                try:
                    parts.extend(split(e['text'], clr))
                except KeyError:
                    pass
                parts.extend(cc)
            elif isinstance(e, (list, tuple)):
                parts.extend(split(e, cc))
            else:
                parts.append(e)
        return parts
    def make_seq():
        if not color: return ''
        r = []
        if clr != oclr:
            if clr is None:
                r.append(0)
            else:
                r.append(clr)
        if bold != obold:
            r.append(1 if bold else 22)
        if not r: return ''
        return '\033[' + ';'.join(map(str, r)) + 'm'
    # Linearize text and color information.
    parts = split(msg)
    # Render into escape sequences.
    oclr, obold = None, False
    clr, bold = None, False
    ret = []
    for p in parts:
        if isinstance(p, str):
            ret.append(make_seq())
            oclr, obold = clr, bold
            ret.append(p)
            continue
        elif p == 0:
            clr, bold = None, False
        elif p == 1:
            bold = True
        elif p == 22:
            bold = False
        elif 30 <= p <= 37:
            clr = p
    ret.append(make_seq())
    return ''.join(ret)

MENTION_RE = re.compile(r'\B@(\S+?)(?=[.,:;!?)]*(\s|$))')

# Nice up @-mentions in a message.
def prepare_message(msg):
    ret = []
    while msg:
        m = MENTION_RE.search(msg)
        if not m:
            ret.append(msg)
            break
        if m.start() != 0:
            ret.append(msg[:m.start()])
        ret.append({'color': 'orange', 'text': m.group(),
                    'mention': m.group()[1:]})
        msg = msg[m.end():]
    return ret

# Scan for @-mentions of the given nick.
def scan_mentions(msg, nick):
    if isinstance(msg, dict):
        if msg.get('mention') == nick:
            return True
        return scan_mentions(msg.get('text'), nick)
    elif isinstance(msg, (list, tuple)):
        for e in msg:
            if scan_mentions(e, nick):
                return True
    return False

class ChatDistributor:
    def __init__(self):
        self.lock = threading.RLock()
        self.handlers = set()
        self._sending = True

    def start(self):
        spawn_thread(self._beacon)

    def _beacon(self):
        while 1:
            time.sleep(10)
            with self.lock:
                for h in self.handlers:
                    h.handle_beacon()

    def add_handler(self, handler):
        with self.lock:
            self.handlers.add(handler)
    def remove_handler(self, handler):
        with self.lock:
            self.handlers.discard(handler)

    def list_users(self):
        with self.lock:
            h = list(self.handlers)
        return [x for x in h if x.nickname]

    def prepare_message(self, msg):
        return prepare_message(msg)

    def join(self, handler, **params):
        logging.info('JOIN id=%d term=%s nick=%r' % (handler.id,
            handler.termtype, handler.nickname))
        self.add_handler(handler)
        self.broadcast(dict(text=[{'color': 'bold', 'text': '***'}, ' ',
            {'color': 'purple', 'text': handler.nickname},
            ' has joined'], **params))
    def leave(self, handler, **params):
        logging.info('LEAVE id=%d' % handler.id)
        self.broadcast(dict(text=[{'color': 'bold', 'text': '***'}, ' ',
            {'color': 'purple', 'text': handler.nickname}, ' has left'],
            **params))
        self.remove_handler(handler)
    def rename(self, handler, old, **params):
        logging.info('RENAME id=%s from=%r to=%r' % (handler.id,
            old, handler.nickname))
        self.broadcast(dict(text=[{'color': 'bold', 'text': '***'}, ' ',
            {'color': 'orange', 'text': old}, ' is now ',
            {'color': 'purple', 'text': handler.nickname}],
            **params))
    def emote(self, handler, message, **params):
        logging.info('EMOTE id=%s nick=%r text=%r' % (handler.id,
            handler.nickname, message))
        self.broadcast(dict(text=[{'color': 'turquiose', 'text': '*'}, ' ',
            {'color': 'purple', 'text': handler.nickname}, ' ',
            self.prepare_message(message)], **params))
    def say(self, handler, message, **params):
        logging.info('SAY id=%s nick=%r text=%r' % (handler.id,
            handler.nickname, message))
        self.broadcast(dict(text=[{'color': 'turquiose', 'text': '<'},
            {'color': 'purple', 'text': handler.nickname},
            {'color': 'turquiose', 'text': '>'}, ' ',
            self.prepare_message(message)], **params))
    def closed(self, handler, **params):
        ok = (not params.get('abrupt'))
        logging.info('%s id=%r from=%r' % ('CLOSE' if ok else 'ABORT',
                                           handler.id, handler.addr))
        self.remove_handler(handler)
        if ok: return
        self.broadcast(dict(text=[{'color': 'bold', 'text': '***'}, ' ',
            {'color': 'purple', 'text': handler.nickname}, ' ',
            {'color': 'red', 'text': 'has left unexpectedly'}], **params))

    def broadcast(self, msg):
        if not self._sending: return
        with self.lock:
            for h in self.handlers:
                h.handle_broadcast(msg)

    def close(self):
        self.broadcast({'text': [{'color': 'bold', 'text': '***'},
            ' Server is closing; goodbye!']})
        self._sending = False
        with self.lock:
            l = list(self.handlers)
            for h in l:
                h.close()

class ClientHandler:
    ST_PREPARING = 'preparing'
    ST_READING = 'reading'
    ST_WRITING = 'writing'
    ST_INTERACTIVE = 'interactive'
    ST_CLOSED = 'closed'

    def __init__(self, distr, ident, sock, addr):
        self.distributor = distr
        self.id = ident
        self.sock = sock
        self.addr = addr
        self._flock = threading.RLock()
        self._rawfile = self.sock.makefile('rwb')
        self.bcqueue = Queue()
        self.file = io.TextIOWrapper(self._rawfile, encoding='ascii',
                                     errors='replace')
        self.nickname = None
        self.termtype = None
        self.alerts = 'off'
        self.state = self.ST_PREPARING
        self.height = None
        self._nl = True

    def read(self, n):
        if self.state == self.ST_CLOSED: return ''
        return self.file.read(n)
    def readline(self):
        if self.state == self.ST_CLOSED: return ''
        return self.file.readline()
    def write(self, dat):
        if self.state == self.ST_CLOSED: return
        with self._flock:
            self.file.write(dat)
        self.file.flush()
    def close(self):
        if self.state == self.ST_CLOSED: return
        self.state = self.ST_CLOSED
        try:
            self.distributor.closed(self,
                abrupt=(self.state != self.ST_PREPARING),
                exclude=self)
            if self.termtype != 'dumb':
                self.file.write('\033[r\033c')
                self.file.flush()
            elif not self._nl:
                self.file.write('\n')
                self.file.flush()
        finally:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except IOError:
                pass

    def print(self, *args, **kwds):
        s = format_print(*args, **kwds)
        if self.state == self.ST_INTERACTIVE:
            if s.endswith('\n'): s = s[:-1]
            self.print_broadcast(s)
        else:
            self.write(s)
    def print_broadcast(self, msg):
        if self.termtype != 'dumb':
            self.write('\0337\033M\n\r' + msg + '\0338')
        else:
            pref = '' if self._nl else '\n'
            self.write(pref + msg)
            self._nl = False

    def term_height(self):
        self.print('# Wait for some text to appear, and press <Return>.')
        self.print('# If none does appear, type "cancel" and <Return>.')
        h = None
        while 1:
            self.write('\033[1000B\033[6n')
            l = self.readline().strip()
            if not l:
                continue
            elif not l.startswith('\033['):
                # "cancel" is handled implicitly.
                return
            elif not l.endswith('R'):
                return
            resp = ''.join(l[2:-1]).split(';')
            if len(resp) != 2:
                return
            try:
                nh = int(resp[0], 10)
            except ValueError:
                return
            if nh != h:
                h = nh
                continue
            return h
    def setup_term(self):
        if self.termtype == 'dumb': return
        self.write('\033[r\033[H\033[2J')
        self.print('# Calibrating terminal...')
        self.height = self.term_height()
        if self.height is None:
            self.print('# Calibration failed; returning to dumb mode.')
            self.termtype = 'dumb'
            return
        self.write('\033[2J\033[1;%sr\033[%s;1H' %
                   (self.height - 1, self.height))

    def handle_line(self, l):
        self._nl = True
        while 1:
            try:
                self.print_broadcast(self.bcqueue.get(False))
            except Empty:
                break
        if self.termtype == 'vte':
            time.sleep(0.05)
        tokens = l.split()
        if not tokens:
            if self.state == self.ST_READING:
                self.state = self.ST_WRITING
        elif tokens[0] == '/quit':
            raise SystemExit
        elif tokens[0] == '/help':
            self.print(HELP)
        elif tokens[0] == '/ping':
            self.print('PONG')
        elif tokens[0] == '/term':
            self.change_term(tokens[1:])
        elif tokens[0] == '/nick':
            self.change_nick(tokens[1:])
        elif tokens[0] == '/alert':
            self.change_alerts(tokens[1:])
        elif tokens[0] == '/ao':
            self.change_alerts(('once',))
        elif tokens[0] == '/join':
            if self.join_room(tokens[1:]):
                return
        elif tokens[0] == '/leave':
            self.leave_room(tokens[1:])
        elif tokens[0] == '/say':
            m = re.search(r'\s+', l)
            self.say(l[m.end():].strip() if m else None)
        elif tokens[0] == '/me':
            m = re.search(r'\s+', l)
            self.emote(l[m.end():].strip() if m else None)
        elif tokens[0] == '/list':
            self.list_users(tokens[1:])
        elif tokens[0].startswith('/'):
            self.print("# No such command!")
        else:
            self.say(l.rstrip(), (self.termtype == 'ansi'))
        if self.state in (self.ST_INTERACTIVE, self.ST_WRITING):
            self.prompt()
    def handle_close(self, ok):
        pass
    def handle_broadcast(self, msg):
        if msg.get('exclude') is self: return
        clr = (self.termtype != 'dumb')
        if self.state in (self.ST_PREPARING, self.ST_CLOSED):
            pass
        elif self.state == self.ST_WRITING:
            self.bcqueue.put(format_message(msg, clr))
        else:
            self.print_broadcast(format_message(msg, clr))
        if self.alerts != 'off':
            if self.alerts == 'once':
                self.alerts = 'off'
            elif self.alerts == 'mention':
                if not scan_mentions(msg, self.nickname):
                    return
            self.write('\a')
    def handle_beacon(self, msg):
        self.write('\0')

    def prompt(self):
        if self.termtype == 'dumb':
            msg = '%s<%s> ' % ('' if self._nl else '\n', self.nickname)
            self._nl = False
        else:
            msg = format_message([{'color': 'turquiose', 'text': '<'},
                {'color': 'purple', 'text': self.nickname},
                {'color': 'turquiose', 'text': '>'}, ' \033[K'], True)
        self.write(msg)

    def change_term(self, args):
        if len(args) == 0:
            if self.termtype is None:
                self.print('# Terminal: <not set>')
            else:
                self.print('# Terminal:', self.termtype)
        elif len(args) != 1 or args[0] not in ('dumb', 'ansi', 'vte'):
            self.print('# USAGE: /term [dumb|ansi|vte]')
        elif self.state != self.ST_PREPARING:
            self.print('# /leave first for changing terminal type.')
        else:
            self.termtype = args[0]
    def change_nick(self, args):
        if len(args) == 0:
            if self.nickname is None:
                self.print('# Nickname: <not set>')
            else:
                self.print('# Nickname: %r' % self.nickname)
        elif len(args) != 1:
            self.print('# USAGE: /nick [<nickname>]')
        else:
            old = self.nickname
            self.nickname = args[0]
            if self.state != self.ST_PREPARING:
                self.distributor.rename(self, old)
    def change_alerts(self, args):
        if len(args) == 0:
            self.print('# Alerts: %s' % self.alerts)
        elif len(args) != 1 or args[0] not in ('off', 'once',
                                               'mention', 'on'):
            self.print('# USAGE: /alert [off|once|mention|on]')
        else:
            self.alerts = args[0]

    def join_room(self, args):
        if self.state != self.ST_PREPARING:
            self.print("# Can't join; already done!")
        elif self.termtype is None:
            self.print('# No terminal type set.')
        elif self.nickname is None:
            self.print('# No nick-name set.')
        else:
            self.setup_term()
            if self.termtype == 'dumb':
                self.state = self.ST_READING
            else:
                self.state = self.ST_INTERACTIVE
            self.print('# Joining room...')
            if self.termtype == 'dumb':
                self.print('# (Press <Return> to type a message.)')
                self._nl = True
                self.distributor.join(self)
                return True
            else:
                self.distributor.join(self)
                return False
    def leave_room(self, args):
        if self.state == self.ST_PREPARING:
            self.print("# Can't leave; not joined at all!")
        else:
            self.distributor.leave(self)
            if self.termtype != 'dumb':
                self.write('\033[r\033[2J')
            elif not self._nl:
                self.print()
                self._nl = True
            self.state = self.ST_PREPARING
            self.print('# Left.')

    def emote(self, msg=None, echo=True):
        if msg is None:
            return
        elif self.state == self.ST_PREPARING:
            self.print("# Can't chat here.")
            return
        params = {}
        if not echo: params['exclude'] = self
        self.distributor.emote(self, msg, **params)
    def say(self, msg=None, echo=True):
        if msg is None:
            return
        elif self.state == self.ST_PREPARING:
            self.print("# Can't chat here.")
            return
        params = {}
        if not echo: params['exclude'] = self
        self.distributor.say(self, msg, **params)
        if self.state == self.ST_WRITING:
            self.state = self.ST_READING

    def list_users(self, args):
        if len(args) != 0:
            self.print('# USAGE: /list')
        else:
            ul = self.distributor.list_users()
            msg = ['# Users online: ']
            if ul:
                for n, i in enumerate(ul):
                    if n: msg.append(',')
                    msg.append({'color': 'orange', 'text': i.nickname})
            else:
                msg.append('<none>')
            self.print(format_message(msg,
                (self.termtype != 'dumb')))

    def __call__(self):
        try:
            ok = True
            self.print(SIGNATURE)
            self.print(COMMENT)
            while 1:
                l = self.readline()
                if not l: break
                self.handle_line(l)
        except Exception:
            ok = False
            raise
        finally:
            self.close()
            self.handle_close(ok)

def mainloop(host, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    distr = ChatDistributor()
    ident = 0
    try:
        while 1:
            c, a = s.accept()
            ident += 1
            logging.info('CONNECTION id=%r from=%r' % (ident, a))
            spawn_thread(ClientHandler(distr, ident, c, a))
            c, a = None, None
    except KeyboardInterrupt:
        return distr

def main():
    # Signal handler.
    def handler(signum, frame):
        raise KeyboardInterrupt
    # Variables.
    host, port, logfile = HOST, PORT, None
    # Parse arguments.
    try:
        it = iter(sys.argv[1:])
        for arg in it:
            if arg == '--help':
                print('USAGE: %s [--help] [--host host] [--port port] '
                      '[--logfile logfile]' % sys.argv[0], file=sys.stderr)
                sys.exit(0)
            elif arg == '--host':
                host = next(it)
            elif arg == '--port':
                port = int(next(it))
            elif arg == '--logfile':
                logfile = next(it)
            else:
                print('WARNING: Unrecognized option %r.' % arg,
                      file=sys.stderr)
    except StopIteration:
        print('ERROR: Option %r missing required value!' % arg,
              file=sys.stderr)
        sys.exit(1)
    except ValueError:
        print('ERROR: Invalid value for option %r!' % arg,
              file=sys.stderr)
        sys.exit(1)
    # Prepare logging
    config = {}
    if logfile is not None: config['filename'] = logfile
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s %(name)s '
        '%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', **config)
    logging.info('WHBCS version=%s' % SIGNATURE.split()[1])
    logging.info('SERVING bind=%s:%s' % (host or '*', port))
    # Install signal handlers.
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    # Run.
    distr = mainloop(host, port)
    if distr: distr.close()
    logging.info('STOPPING')

if __name__ == '__main__': main()

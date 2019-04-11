import json
import os
import sqlite3
import time
import types

from hashlib import sha256

LOGGERS = []

class Blob:
    """Automatically encode a binary string."""
    def __init__(self, s, log_bytes, log_hash):
        self.s = s
        self.log_bytes = log_bytes
        self.log_hash = log_hash

    @property
    def blob(self):
        return sqlite3.Binary(self.s if self.log_bytes else b'')

    @property
    def length(self):
        return len(self.s)

    @property
    def sha256(self):
        return sha256(self.s).hexdigest() if (self.s and self.log_hash) else b''


class FileLogger(object):
    FILE_PREAMBLE = "\n" + "#"*80 + "# Starting run at %s\n" % time.time() + "#" * 80 + "\n\n"
    def __init__(self, log_file=None, log_all=False):
        self.log_file = log_file
        self.logged_calls = set()
        self.log_all = log_all

        if not os.path.exists(os.path.dirname(self.log_file)):
            os.makedirs(os.path.dirname(self.log_file))

        fhandle = open(self.log_file, 'a' if os.path.exists(self.log_file) else 'w')
        fhandle.write(self.FILE_PREAMBLE)
        self._write = fhandle.write

    def add_call(self, call):
        self.logged_calls.add(call)

    def format(self, info):
        kwargs = {k: str(v)[:500] for k, v in info.items() if k[0] != '_'}
        return "%s: state: %s:   %s\n" % (info['_call'], info['_state'], json.dumps(kwargs))

    def log(self, info):
        if info['_call'] in self.logged_calls or self.log_all:
            self._write(self.format(info))


class DBLogger(object):
    def __init__(self, log_db=None, log_all=False, log_bytes=False, log_hash=False, conf="db.conf"):
        self.log_db = log_db
        self.log_bytes = log_bytes
        self.log_hash = log_hash
        self.logged_calls = set()
        self.log_all = log_all
        self.conf = conf

        if self.log_db and not os.path.exists(os.path.dirname(self.log_db)):
            os.makedirs(os.path.dirname(self.log_db))
        self.conn = sqlite3.connect(self.log_db)
        self.cur = self.conn.cursor()

        with open(self.conf) as fh:
            self.config = json.load(fh)

        for table in self.config['db']['table_creates']:
            self.cur.execute(table)
        self.conn.commit()

    def add_call(self, call):
        self.logged_calls.add(call)

    def make_composite_key(self, offset, length):
        """Make a composite key. Assumes: offset < 2**40, length % 4096 == 0, length < 2**20"""
        return (offset << 8) + (length >> 12)

    def format(self, info):
        # Handle log_all separately
        inserts = []
        if self.log_all:
            kwargs = {k: str(v)[:500] for k, v in info.items() if k[0] != '_'}
            info['_kwargs'] = json.dumps(kwargs)

        queries = [self.config['db']['queries']['call']] if self.log_all else []
        if info['_call'] in self.logged_calls:
            queries += self.config['db']['queries'][info['_call']]

            # Normalize call return buffer
            res = info.get('_res')
            if info.get('buf'):             # write operations
                buf = info['buf']
            elif isinstance(res, bytes):
                buf = res
            elif isinstance(res, str):
                buf = res.encode('utf8')
            elif isinstance(res, types.GeneratorType):
                _res = [i for i in res]
                buf = str(_res).encode('utf8')
            else:
                buf = str(res).encode('utf8')
            blob = Blob(buf, self.log_bytes, self.log_hash)
            info['_buffer'] = blob.blob
            info['_buffer_length'] = blob.length
            info['_buffer_hash'] = blob.sha256
            info['_composite_key'] = self.make_composite_key(info['offset'], info.get('length', blob.length))

        for query in queries:
            inserts.append((query['query'], tuple(info[i] for i in query['args'])))

        return inserts

    def log(self, info):
        for query, args in self.format(info):
            self.cur.execute(query, args)
        self.conn.commit()


def init_logging(args):
    if args.log_file:
        LOGGERS.append(FileLogger(args.log_file, args.log_all))
    if args.log_db:
        LOGGERS.append(DBLogger(args.log_db, args.log_all, args.log_bytes, args.log_hash, conf=args.config))
    for call in args.call_log:
        for logger in LOGGERS:
            logger.add_call(call)
    if not LOGGERS:
        raise Exception("No logging configured!")


def log(info):
    for logger in LOGGERS:
        logger.log(info)


def logs(func):
    def wrapper(*args, **kwargs):
        info = dict(zip(func.__code__.co_varnames, args))
        info.update(kwargs)
        info['_call'] = func.__name__
        info['_state'] = 'pre-run'
        try:
            res = func(*args, **kwargs)
            info['_res'] = res
            info['_state'] = 'post-run'

            # Log and return
            log(info)
            return res
        except Exception as e:
            info['_state'] = 'error'
            info['buf'] = str(e).encode('utf8')
            log(info)
            raise

    return wrapper

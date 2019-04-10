#!/usr/bin/env python3

from __future__ import with_statement

import argparse
import os
import sys
import errno
import sqlite3
import json
import time
import types
from hashlib import sha256

from fuse import FUSE, FuseOSError, Operations

LOG_FILE = None
LOG_DB = None
LOG_CALLS = set()
LOG_ALL = False

TABLES = [
"""CREATE TABLE IF NOT EXISTS func_calls(
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       call CHAR(20) NOT NULL,
       kwargs TEXT NOT NULL,
       retval TEXT NOT NULL
)""",
"""CREATE TABLE IF NOT EXISTS reads(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path CHAR(200) NOT NULL,
    length INT NOT NULL,
    offset INT NOT NULL,
    buffer_length INT NOT NULL,
    buffer_hash CHAR(64) NOT NULL,
    data BLOB NOT NULL
)""",
"""CREATE TABLE IF NOT EXISTS writes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path CHAR(200) NOT NULL,
    offset INT NOT NULL,
    buffer_length INT NOT NULL,
    buffer_hash CHAR(64) NOT NULL,
    data BLOB NOT NULL
)"""
]
     

LOGGERS = {
    "call": ("INSERT INTO func_calls (call, kwargs, retval) VALUES (?, ?, ?)",
             ('_call', 'kwargs', '_retval')),
    "read": ("INSERT INTO reads (path, length, offset, buffer_length, buffer_hash, data) VALUES (?, ?, ?, ?, ?, ?)",
             ('path', 'length', 'offset', '_buffer_length', '_buffer_hash', '_buffer')),
    "write": ("INSERT INTO writes (path, offset, buffer_length, buffer_hash, data) VALUES (?, ?, ?, ?, ?)",
              ('path', 'offset', '_buffer_length', '_buffer_hash', '_buffer'))
}

class Blob:
    """Automatically encode a binary string."""
    def __init__(self, s):
        self.s = s

    @property
    def blob(self):
        return sqlite3.Binary(self.s)

    @property
    def length(self):
        return len(self.s)

    @property
    def sha256(self):
        return sha256(self.s).hexdigest() if self.s else b''


def log_init(logfnm, logdb):
    global LOG_FILE
    global LOG_DB
    if logfnm:
        if not os.path.exists(logfnm):
            LOG_FILE = open(logfnm, 'w')
        else:
            LOG_FILE = open(logfnm, 'a')
        LOG_FILE.write("\n\n########################\n"
                       "# Starting run at %s\n#########################\n\n" % time.time())

    if logdb:
        conn = sqlite3.connect(logdb)
        LOG_DB = (conn, conn.cursor())
        for table in TABLES:
            print("Creating table %s" % table)
            LOG_DB[1].execute(table)
        LOG_DB[0].commit()

def log(info):
    if not LOG_ALL and info['_call'] not in LOG_CALLS:
        return
    kwargs = {k: str(v)[:500] for k, v in info.items() if k[0] != '_'}
    if LOG_FILE:
        LOG_FILE.write("%s: state: %s:   %s\n" % (info['_call'], info['_state'], json.dumps(kwargs)))
    if LOG_DB:
        if LOG_ALL:
            LOGDB.execute(LOGGERS['call'], (info[i], json.dumps(kwargs), json.dumps(info.get('buf'))))
        if info['_call'] in LOG_CALLS:
            info['_buffer_length'] = info['_buf'].length
            info['_buffer_hash'] = info['_buf'].sha256
            info['_buffer'] = info['_buf'].blob
            query, args = LOGGERS[info['_call']]
            LOG_DB[1].execute(query, tuple(info[i] for i in args))
        LOG_DB[0].commit()

def logs(func):
    def wrapper(*args, **kwargs):
        info = dict(zip(func.__code__.co_varnames, args))
        info.update(kwargs)
        info['_call'] = func.__name__
        info['_state'] = 'pre-run'
        info['_buf'] = Blob(b'')
        try:
            log(info)
            res = func(*args, **kwargs)
            if isinstance(res, bytes):
                buf = res
            elif isinstance(res, str):
                buf = res.encode('utf8')
            elif isinstance(res, types.GeneratorType):
                _res = [i for i in res]
                res = iter(_res)
                buf = str(_res).encode('utf8')
            else:
                buf = str(res).encode('utf8')
            info['_buf'] = Blob(buf)
            info['_state'] = 'post-run'
            log(info)
            return res
        except Exception as e:
            info['_state'] = 'error'
            info['buf'] = str(e).encode('utf8')
            log(info)
            raise
    return wrapper


class Passthrough(Operations):
    def __init__(self, root):
        self.root = root

    # Helpers
    # =======

    def _full_path(self, partial):
        partial = partial.lstrip("/")
        path = os.path.join(self.root, partial)
        return path

    # Filesystem methods
    # ==================

    @logs
    def access(self, path, mode):
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    @logs
    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    @logs
    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    @logs
    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                     'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

    @logs
    def readdir(self, path, fh):
        full_path = self._full_path(path)

        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    @logs
    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    @logs
    def mknod(self, path, mode, dev):
        return os.mknod(self._full_path(path), mode, dev)

    @logs
    def rmdir(self, path):
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    @logs
    def mkdir(self, path, mode):
        return os.mkdir(self._full_path(path), mode)

    @logs
    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    @logs
    def unlink(self, path):
        return os.unlink(self._full_path(path))

    @logs
    def symlink(self, name, target):
        return os.symlink(name, self._full_path(target))

    @logs
    def rename(self, old, new):
        return os.rename(self._full_path(old), self._full_path(new))

    @logs
    def link(self, target, name):
        return os.link(self._full_path(target), self._full_path(name))

    @logs
    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)

    # File methods
    # ============

    @logs
    def open(self, path, flags):
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    @logs
    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    @logs
    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    @logs
    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    @logs
    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    @logs
    def flush(self, path, fh):
        return os.fsync(fh)

    @logs
    def release(self, path, fh):
        return os.close(fh)

    @logs
    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)


def main(mount_point, root):
    FUSE(Passthrough(root), mount_point, nothreads=True, foreground=True)


if __name__ == '__main__':
    argp = argparse.ArgumentParser(description="Perform logging of mass storage operations")
    argp.add_argument('-m', '--mount_point', help="Mount point to use")
    argp.add_argument('-r', '--root', help="Root to mount at mount point")
    argp.add_argument('-l', '--log_file', default=None, help="Logfile to use.")
    argp.add_argument('-d', '--log_db', default=None, help="Log to an sqlite DB instead")
    argp.add_argument('-a', '--log_all', action="store_true", help="Log everything (DO NOT USE)")
    argp.add_argument('-c', '--call_log', action='append', help="Use to log only these calls (read, write, etc)")
    argp.add_argument('--log_hash', action="store_true", help="Store a hash of read and write buffers")
    argp.add_argument('--log_bytes', action="store_true", help="Store the full bytes of read and write buffers as hex")

    args = argp.parse_args()
    for call in args.call_log:
        LOG_CALLS.add(call)
    LOG_ALL = bool(args.log_all)
    log_init(args.log_file, args.log_db)

    main(args.mount_point, args.root)

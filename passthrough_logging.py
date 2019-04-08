#!/usr/bin/env python

from __future__ import with_statement

import argparse
import os
import sys
import errno
import sqlite3
import marshal
import json
from hashlib import sha256

from fuse import FUSE, FuseOSError, Operations

LOGFILE = None
LOGDB = None
LOG_CALLS = set()
LOG_ALL = False

TABLES = [
"""CREATE TABLE IF NOT EXISTS func_calls (
       id BIGINT UNSIGNED NOT NULL AUTOINCREMENT,
       call CHAR(20) NOT NULL,
       kwargs TEXT NOT NULL,
       retval TEXT NOT NULL
       PRIMARY KEY (id)
)""",
"""CREATE TABLE IF NOT EXISTS reads (
    id BIGINT UNSIGNED NOT NULL AUTOINCREMENT,
    path CHAR(100) NOT NULL,
    length INT NOT NULL,
    offset INT NOT NULL,
    buffer_length INT,
    buffer_hash CHAR(64),
    PRIMARY KEY (id)
""",
"""CREATE TABLE IF NOT EXISTS writes (
    id BIGINT UNSIGNED NOT NULL AUTOINCREMENT,
    path CHAR(100) NOT NULL,
    offset INT NOT NULL,
    buffer_length INT NOT NULL,
    buffer_hash CHAR(64) NOT NULL,
    PRIMARY KEY (id)
"""
]
     

LOGGERS = {
    "call": ("INSERT INTO func_calls (call, args, kwargs, retval) VALUES (%s, %s, %s, %s, %s)", ('ts', 'call', 'args, 'kwargs', 'retval')),
    "read": ("INSERT INTO reads (path, length, offset, buffer_length, buffer_hash) VALUES (%s, %s, %s, %s, %s)", ('path, 'length', 'offset', 'buffer_length', 'buffer_hash')),
    "write": ("INSERT INTO writes (path, offset, buffer_length, buffer_hash) VALUES (%s, %s, %s, %s)" ('path', 'offset', 'buffer_length', 'buffer_hash'))
}

def log_init(logfnm, logdb):
    global LOGFILE
    global LOGDB
    if logfnm:
        if not os.path.exists(logfnm):
            LOGFILE = open(logfnm, 'w')
        else:
            LOGFILE = open(logfnm, 'a')

    if logdb:
        conn = sqlite3.connect(logdb)
        LOGDB = conn.cursor()
        for table in TABLES:
            LOGDB.execute(table)


def log(call, message):
    if not call in LOGCALLS:
        return
    if LOGFILE:
        LOGFILE.write("%s: %s\n" % (call, message))

def logdb(call, info):
    def run_query():
        if not call in LOGGERS:
            return
        query, args = LOGGERS.get(call)
        LOGDB.execute(query, (info[i] for i in args))

    info['call'] = call
    info['buffer_length'] = len(buf)
    info['buffer_hash'] = sha256(buf).hexdigest()
    if LOG_ALL:
        info['retval'] = info.get('buf')
        LOGDB.execute(LOGGERS['call'], {k: str(v) for k, v in info.iteritems()})
    run_query()

def logwrapper(func):
    def wrapper(*args, **kwargs):
        info = dict(zip(func.__code__.co_varnames, args))
        info.update(kwargs)
        log(call, "args, kwargs %s, %s" % (args, kwargs))
        try:
            res = func(*args, **kwargs)
            info['buf'] = marshal.dumps(res)
            log(call, "yielded %s" % (res))
            logdb(call, info)
        except Exception as e:
            log(call, "raised %s" % e)
            info['buf']: str(e).encode('utf8')
            logdb(call, info)
        return res
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

    @logwrapper
    def access(self, path, mode):
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    @logwrapper
    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    @logwrapper
    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    @logwrapper
    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                     'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

    @logwrapper
    def readdir(self, path, fh):
        full_path = self._full_path(path)

        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    @logwrapper
    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    @logwrapper
    def mknod(self, path, mode, dev):
        return os.mknod(self._full_path(path), mode, dev)

    @logwrapper
    def rmdir(self, path):
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    @logwrapper
    def mkdir(self, path, mode):
        return os.mkdir(self._full_path(path), mode)

    @logwrapper
    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    @logwrapper
    def unlink(self, path):
        return os.unlink(self._full_path(path))

    @logwrapper
    def symlink(self, name, target):
        return os.symlink(name, self._full_path(target))

    @logwrapper
    def rename(self, old, new):
        return os.rename(self._full_path(old), self._full_path(new))

    @logwrapper
    def link(self, target, name):
        return os.link(self._full_path(target), self._full_path(name))

    @logwrapper
    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)

    # File methods
    # ============

    @logwrapper
    def open(self, path, flags):
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    @logwrapper
    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    @logwrapper
    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    @logwrapper
    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    @logwrapper
    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    @logwrapper
    def flush(self, path, fh):
        return os.fsync(fh)

    @logwrapper
    def release(self, path, fh):
        return os.close(fh)

    @logwrapper
    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)


def main(mountpoint, root):
    FUSE(Passthrough(root), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    import argparse
    argp = argparse.ArgumentParser()
    argp.add_argument('-m', '--mountpoint', help="Mountpoint to use")
    argp.add_argument('-r', '--root', help="Root to mount at mountpoint")
    argp.add_argument('-l', '--logfile', help="Logfile to use.")
    argp.add_argument('-d', '--logdb', help="Log to an sqlite DB instead")
    argp.add_argument('-a', '--logall', help="Log everything (DO NOT USE)")
    argp.add_argument('-c', '--calllog', action='append', help="Use multiple to log only these calls (read, write, etc)")

    main(sys.argv[2], sys.argv[1])

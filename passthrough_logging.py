#!/usr/bin/env python

from __future__ import with_statement

import os
import sys
import errno

from fuse import FUSE, FuseOSError, Operations

LOGFILE = None

def log(message):
    global LOGFILE
    if not LOGFILE:
        LOGFILE = open('/var/log/fuse.log', 'a')
    LOGFILE.write(message)


def logwrapper(func):
    def wrapper(*args, **kwargs):
        log("Calling func %s with args, kwargs %s, %s\n" % (func.__name__, args, kwargs))
        res = func(*args, **kwargs)
        log("Calling func %s yielded %s\n" % (func.__name__, res))
        return res
    return wrapper


class Passthrough(Operations):
    @logwrapper
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
    main(sys.argv[2], sys.argv[1])

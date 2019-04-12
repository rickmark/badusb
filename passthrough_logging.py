#!/usr/bin/env python3

from __future__ import with_statement

import argparse
import os
import errno

from fuse import FUSE, FuseOSError, Operations

from logger import logs, init_logging
from injector import inject, init_injector
from gpt import parse_gpt, READS

class Passthrough(Operations):
    def __init__(self, root, second_root=None, switch_after=1):
        self.root = root
        self.second_root = second_root
        self.switch_after = switch_after

        self.initial_gpt_reads = len(READS)

    @property
    def read_count(self):
        return len(READS) - self.initial_gpt_reads

    # Helpers
    # =======

    def _full_path(self, partial):
        partial = partial.lstrip("/")
        if self.read_count > self.switch_after and self.second_root:
            path = os.path.join(self.second_root, partial)
        else:
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
    @parse_gpt
    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        orig_data = os.read(fh, length)
        new_data = inject(path, length, offset, orig_data)
        return new_data

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


def main(args):
    FUSE(Passthrough(args.root, args.second_root, args.num_reads), args.mount_point, nothreads=True, foreground=True)


if __name__ == '__main__':
    argp = argparse.ArgumentParser(description="Perform logging of mass storage operations")
    argp.add_argument('-m', '--mount_point', help="Mount point to use")
    argp.add_argument('-s', '--second_root', default=None, help="Second root to switch to")
    argp.add_argument('-n', '--num_reads', type=int, default=1, help="Switch to second root after this many reads")
    argp.add_argument('-r', '--root', help="Root to mount at mount point")
    argp.add_argument('-l', '--log_file', default=None, help="Logfile to use.")
    argp.add_argument('-d', '--log_db', default=None, help="Log to an sqlite DB instead")
    argp.add_argument('-a', '--log_all', action="store_true", help="Log everything (DO NOT USE)")
    argp.add_argument('-c', '--call_log', default=['write', 'read'], action='append',
                       help="Use to log only these calls (read, write, etc)")
    argp.add_argument('--log_hash', action="store_true", help="Store a hash of read and write buffers")
    argp.add_argument('--log_bytes', action="store_true", help="Store the full bytes of r/w buffers")
    argp.add_argument('--config', default='config.json', help="Path to a config file")

    args = argp.parse_args()
    init_logging(args)
    init_injector(args)

    main(args)

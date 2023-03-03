#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# NOTE: this is a slightly different hash than the one used in SW3

import sys
import random
import struct


def get_function_hash(seed, function_name, is_syscall=True):
    function_hash = seed
    #function_name = function_name.replace('_', '')
    if is_syscall and function_name[:2] == 'Nt':
        function_name = 'Zw' + function_name[2:]
    name = function_name + '\0'
    ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))
    rol8 = lambda v: ((v << 8) & (2 ** 32 - 1)) | ((v >> 24) & (2 ** 32 - 1))
    rox8 = lambda v: (rol8(v) if (v % 2) != 0 else ror8(v))

    for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
        partial_name_short = struct.unpack('<H', segment.encode())[0]
        function_hash ^= partial_name_short + rox8(function_hash)

    return function_hash


def main():
    seed = 0x1337c0de
    function_name = sys.argv[1]
    new_hash = get_function_hash(seed, function_name, is_syscall=True)
    exit(f'{function_name}: 0x{new_hash:08X}')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        exit(f'usage: {sys.argv[0]} <function_name>')
    main()

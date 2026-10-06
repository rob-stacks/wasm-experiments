#!/usr/bin/env python3
"""Attribute a wasm module's code bytes to Rust crates, using its "name" section.

usage: wasm_by_crate.py module.wasm [top-N]
"""
import collections
import re
import sys


def leb(b, i):
    r = s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        s += 7
        if x < 0x80:
            return r, i


def crate_of(name):
    """First crate in a Rust symbol (v0 `_R...` or legacy `_ZN...`/demangled)."""
    if name.startswith('_R'):
        # v0 mangling: crate roots are `C<disambiguator>_<len><ident>` or `C<len><ident>`
        m = re.search(r'C(?:s[0-9A-Za-z]*_)?(\d+)', name)
        if m:
            start = m.end()
            return name[start:start + int(m.group(1))]
    m = re.match(r'[<&\s]*([A-Za-z_][A-Za-z0-9_]*)::', name)
    return m.group(1) if m else name


def analyze(path):
    b = open(path, 'rb').read()
    i, sizes, names, nimports = 8, [], {}, 0
    while i < len(b):
        sid = b[i]
        size, i = leb(b, i + 1)
        end = i + size
        if sid == 2:  # imports: function imports shift function indices
            n, j = leb(b, i)
            for _ in range(n):
                for _ in range(2):
                    l, j = leb(b, j)
                    j += l
                kind = b[j]
                j += 1
                if kind != 0:
                    sys.exit('only function imports supported')
                _, j = leb(b, j)
                nimports += 1
        elif sid == 10:  # code
            n, j = leb(b, i)
            for _ in range(n):
                l, j = leb(b, j)
                sizes.append(l)
                j += l
        elif sid == 0:  # custom: "name" -> function names
            l, j = leb(b, i)
            if b[j:j + l] == b'name':
                j += l
                while j < end:
                    sub = b[j]
                    sl, j = leb(b, j + 1)
                    if sub == 1:
                        n, k = leb(b, j)
                        for _ in range(n):
                            idx, k = leb(b, k)
                            l2, k = leb(b, k)
                            names[idx] = b[k:k + l2].decode('utf8', 'replace')
                            k += l2
                    j += sl
        i = end
    by = collections.Counter()
    for f, s in enumerate(sizes):
        name = names.get(f + nimports, '?')
        by[crate_of(name)] += s
    return sum(sizes), by, len(names)


if __name__ == '__main__':
    total, by, named = analyze(sys.argv[1])
    top = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    print(f'{sys.argv[1]}: {total:,} code bytes, {named} named functions')
    for k, v in by.most_common(top):
        print(f'  {v:>9,}  {v / total:6.1%}  {k}')

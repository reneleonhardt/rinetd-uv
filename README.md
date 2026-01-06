# rinetd-uv - Internet Redirection Server

**rinetd-uv** is a modernized implementation of the rinetd internet redirection server, rewritten to use the libuv event loop library.

Originally by Thomas Boutell and Sam Hocevar. This libuv-based implementation maintains backward compatibility with the original rinetd configuration format while providing significantly improved performance through modern event-driven I/O.

Released under the terms of the GNU General Public License, version 2 or later.

## About

This program efficiently redirects TCP and UDP connections from one IP address/port combination to another. It is useful when operating virtual servers, firewalls, and similar network infrastructure.

**Key Features:**
- Event-driven I/O using libuv (high performance, low overhead)
- Configurable buffer sizes for memory optimization
- Zero-copy buffer forwarding
- Both TCP and UDP support
- IPv4 and IPv6 support
- Allow/deny rules for access control

## Quick Start

To build under Unix, run `./bootstrap` to create the configuration
files, then `./configure` to create the build files, and then type
`make` to build rinetd-uv. To install, type `make install` as root.

For documentation run `make install`, then type `man rinetd-uv` for
details. Or, read `index.html` in your browser, or `DOCUMENTATION.md`.

## Documentation

- **DOCUMENTATION.md** - Complete user documentation
- **BUILD.md** - Build requirements and instructions
- **BUFFER_OPTIMIZATION.md** - Performance tuning guide
- **Man page**: `man rinetd-uv` (after installation)

## Differences from Original rinetd

While maintaining configuration file compatibility, rinetd-uv features:
- Complete rewrite using libuv event loop (vs. select())
- Configurable buffer sizes (1 KB to 1 MB)
- Modern C99 codebase with improved error handling
- Zero-copy forwarding for better performance

Original rinetd: https://github.com/samhocevar/rinetd


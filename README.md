
# GitSiphon

A high-performance async git repository dumper.

## Features

- **Async downloads** - Uses `aiohttp` for concurrent requests (50+ simultaneous)
- **Terminal output** - Progress bars and logs
- **Smart retry logic** - Automatic retry with backoff
- **Two dumping modes**:
  - Fast path: Directory listing available (uses wget-style recursive download)
  - Sequential: No directory listing (discovers files via refs and objects)
- **Proxy support** - HTTP and SOCKS proxies
- **Client certificates** - PKCS#12 certificate support

## Install

from source:
```bash
pip install -r requirements.txt
python gitsiphon.py http://website.com/.git ~/output
```

## Usage

```bash
gitsiphon http://website.com/.git ~/output
```

Options:
```
--proxy PROXY              Use proxy (socks5://host:port)
--client-cert-p12 FILE    PKCS#12 certificate
--client-cert-p12-password PASS  Certificate password
-j, --jobs N              Concurrent requests (default: 50)
-r, --retry N             Retry attempts (default: 3)
-t, --timeout N           Timeout in seconds (default: 10)
-u, --user-agent STRING   Custom user-agent
-H, --header NAME=VALUE   Additional headers
-v, --verbose             Verbose output
```

## Performance

GitSiphon uses Python's `asyncio` with `aiohttp` to perform **50+ simultaneous HTTP requests**, compared to git-dumper's 10 worker processes with blocking I/O. This results in **dramatically faster downloads**, especially on high-latency connections.

## How It Works

GitSiphon attempts two methods:

1. **Directory Listing** (Fast): If `.git/` is listable via HTTP, recursively downloads all files then runs `git checkout`.

2. **Sequential Discovery** (Thorough):
   - Fetches common git files (HEAD, index, hooks, etc.)
   - Finds refs by analyzing packed-refs, logs, and config
   - Extracts object hashes from refs
   - Downloads all discovered objects
   - Runs `git checkout` to reconstruct working tree

## Disclaimer

**Use at your own risk!** Downloading proprietary code may be illegal. This tool is intended for security testing only.

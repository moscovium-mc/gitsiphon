#!/usr/bin/env python3
"""
GitSiphon - Advanced Git Repository Dumper
A high-performance tool to dump git repositories from web servers.
"""
import argparse
import asyncio
import logging
import os
import re
import socket
import sys
import urllib.parse
from collections import deque
from contextlib import closing
from pathlib import Path

import aiohttp
import bs4
import socks
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
)

console = Console()

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)],
)
log = logging.getLogger("gitsiphon")


def printf(fmt, *args, **kwargs):
    """Simple printf wrapper for logging."""
    msg = fmt % args if args else fmt
    log.info(msg, **kwargs)


def is_html(response):
    """Check if response is HTML."""
    return (
        "Content-Type" in response.headers
        and "text/html" in response.headers["Content-Type"]
    )


def is_safe_path(path):
    """Prevent directory traversal attacks."""
    if path.startswith("/"):
        return False
    safe_path = os.path.expanduser("~")
    return (
        os.path.commonpath(
            (os.path.realpath(os.path.join(safe_path, path)), safe_path)
        )
        == safe_path
    )


def get_indexed_files(response):
    """Extract files from directory index HTML."""
    html = bs4.BeautifulSoup(response.text, "html.parser")
    files = []
    for link in html.find_all("a"):
        url = urllib.parse.urlparse(link.get("href"))
        if (
            url.path
            and is_safe_path(url.path)
            and not url.scheme
            and not url.netloc
        ):
            files.append(url.path)
    return files


def verify_response(response):
    """Validate HTTP response."""
    if response.status != 200:
        return False, f"[-] Status code {response.status}"
    if response.content_length == 0:
        return False, "[-] Zero-length body"
    if is_html(response):
        return False, "[-] Received HTML instead of file"
    return True, None


def create_intermediate_dirs(path):
    """Create intermediate directories if needed."""
    dirname, basename = os.path.split(path)
    if dirname and not os.path.exists(dirname):
        try:
            os.makedirs(dirname)
        except FileExistsError:
            pass  # Handle race condition


def get_referenced_sha1(obj):
    """Extract referenced SHA1 hashes from git object."""
    objs = []
    if hasattr(obj, 'tree'):
        objs.append(obj.tree.decode() if isinstance(obj.tree, bytes) else obj.tree)
    if hasattr(obj, 'parents'):
        for parent in obj.parents:
            objs.append(parent.decode() if isinstance(parent, bytes) else parent)
    return objs


def sanitize_file(filepath):
    """Comment out unsafe git config lines."""
    assert os.path.isfile(filepath), f"{filepath} is not a file"
    unsafe = r"^\s*(fsmonitor|sshcommand|askpass|editor|pager)"
    with open(filepath, 'r+') as f:
        content = f.read()
        modified = re.sub(unsafe, r'# \g<0>', content, flags=re.IGNORECASE)
        if content != modified:
            printf(f"Warning: '{filepath}' was sanitized")
            f.seek(0)
            f.write(modified)


class GitSiphon:
    """Main class for git repository dumping."""

    def __init__(self, url, directory, jobs=50, retry=3, timeout=10,
                 user_agent=None, headers=None, proxy=None, client_cert=None,
                 client_cert_password=None):
        self.url = url.rstrip("/")
        self.directory = directory
        self.jobs = jobs
        self.retry = retry
        self.timeout = timeout
        self.proxy = proxy
        self.session = None
        self.client_cert = client_cert
        self.client_cert_password = client_cert_password
        self.downloaded = set()
        self.pending = set()
        self.lock = asyncio.Lock()
        
        # Setup headers
        self.headers = {"User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"}
        if headers:
            for h in headers:
                if "=" in h:
                    k, v = h.split("=", 1)
                    self.headers[k.strip()] = v.strip()

    async def init_session(self):
        """Initialize async HTTP session."""
        connector = aiohttp.TCPConnector(limit=self.jobs, limit_per_host=self.jobs)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        # Build trust manager for HTTPS
        ssl_context = None
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self.headers,
            ssl=ssl_context,
        )

    async def close(self):
        """Close HTTP session."""
        if self.session:
            await self.session.close()

    def normalize_url(self):
        """Normalize base URL by removing .git/HEAD suffixes."""
        for suffix in ["HEAD", ".git/HEAD", ".git"]:
            if self.url.endswith(suffix):
                self.url = self.url[:-len(suffix)]
        self.url = self.url.rstrip("/")

    async def fetch(self, path, allow_redirects=True):
        """Fetch a path with retry logic."""
        url = f"{self.url}/{path}"
        
        for attempt in range(self.retry):
            try:
                async with self.session.get(
                    url, 
                    allow_redirects=allow_redirects,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    return resp
            except asyncio.TimeoutError:
                if attempt == self.retry - 1:
                    raise
            except Exception as e:
                if attempt == self.retry - 1:
                    raise
                await asyncio.sleep(0.1 * (attempt + 1))

    async def download_file(self, path, is_dir=False):
        """Download a single file."""
        async with self.lock:
            if path in self.downloaded:
                return []
            self.downloaded.add(path)

        try:
            response = await self.fetch(path, allow_redirects=not is_dir)
            printf(f"[-] Fetching {path} [{response.status}]")

            if response.status == 200:
                if is_dir and is_html(response):
                    files = get_indexed_files(response)
                    return [path + f for f in files]
                
                valid, err = verify_response(response)
                if not valid:
                    log.warning(f"{err}: {path}")
                    return []
                
                abspath = os.path.abspath(os.path.join(self.directory, path))
                create_intermediate_dirs(abspath)
                
                content = await response.read()
                with open(abspath, "wb") as f:
                    f.write(content)
                    
            elif response.status in (301, 302) and is_dir:
                loc = response.headers.get("Location", "")
                if loc.endswith(path + "/"):
                    return [path + "/"]
            
            return []
        except Exception as e:
            log.error(f"Error downloading {path}: {e}")
            return []

    async def find_refs(self, path):
        """Find git refs in a file."""
        try:
            response = await self.fetch(path)
            printf(f"[-] Finding refs in {path} [{response.status}]")
            
            if response.status != 200:
                return []
            
            text = await response.text()
            abspath = os.path.abspath(os.path.join(self.directory, path))
            create_intermediate_dirs(abspath)
            
            with open(abspath, "w") as f:
                f.write(text)
            
            # Extract refs
            tasks = []
            for ref in re.findall(r"(refs(/[a-zA-Z0-9\-\.\_\*]+)+)", text):
                ref = ref[0]
                if not ref.endswith("*") and is_safe_path(ref):
                    tasks.append(f".git/{ref}")
                    tasks.append(f".git/logs/{ref}")
            return tasks
        except Exception as e:
            log.error(f"Error finding refs in {path}: {e}")
            return []

    async def find_objects(self, obj_hash):
        """Find objects referenced by a commit."""
        path = f".git/objects/{obj_hash[:2]}/{obj_hash[2:]}"
        
        async with self.lock:
            if path in self.downloaded:
                return []
            self.downloaded.add(path)

        try:
            response = await self.fetch(path)
            if response.status != 200:
                return []
            
            printf(f"[-] Fetching object {obj_hash[:8]}...")
            
            abspath = os.path.abspath(os.path.join(self.directory, path))
            create_intermediate_dirs(abspath)
            
            content = await response.read()
            with open(abspath, "wb") as f:
                f.write(content)
            
            return []  # Object parsing would require dulwich
        except Exception:
            return []

    async def check_git_head(self):
        """Verify .git/HEAD exists and is valid."""
        try:
            response = await self.fetch(".git/HEAD", allow_redirects=False)
            printf(f"[-] Testing .git/HEAD [{response.status}]")
            
            if response.status != 200:
                return False
                
            text = await response.text()
            if not re.match(r"^(ref:.*|[0-9a-f]{40})$", text.strip()):
                log.error(".git/HEAD is not a valid git HEAD file")
                return False
            return True
        except Exception as e:
            log.error(f"Error checking .git/HEAD: {e}")
            return False

    async def dump_directory_listing(self):
        """Dump using directory listing (fastest method)."""
        printf("[-] Directory listing available, using fast path")
        
        tasks = [".git/", ".gitignore"]
        while tasks:
            batch = tasks[:self.jobs]
            tasks = tasks[self.jobs:]
            results = await asyncio.gather(*[self.download_file(p, p.endswith("/")) for p in batch])
            for r in results:
                tasks.extend(r)
        
        # Sanitize and checkout
        os.chdir(self.directory)
        sanitize_file(".git/config")
        
        # Run git checkout
        import subprocess
        proc = subprocess.run(["git", "checkout", "."], capture_output=True)
        if proc.returncode != 0:
            log.warning("git checkout had issues, partial dump may still be useful")
        
        return True

    async def dump_sequential(self):
        """Dump using sequential file discovery (slower but more thorough)."""
        printf("[-] Using sequential discovery mode")
        
        # Fetch common files
        common_files = [
            ".gitignore", ".git/COMMIT_EDITMSG", ".git/description",
            ".git/index", ".git/info/exclude", ".git/objects/info/packs",
        ]
        
        # Add hooks
        for hook in ["applypatch-msg", "commit-msg", "post-commit", "post-receive",
                     "post-update", "pre-applypatch", "pre-commit", "pre-push",
                     "pre-rebase", "pre-receive", "prepare-commit-msg", "update"]:
            common_files.append(f".git/hooks/{hook}.sample")
        
        # Fetch common files in parallel
        await asyncio.gather(*[self.download_file(f) for f in common_files])
        
        # Find refs
        ref_files = [".git/HEAD", ".git/config", ".git/FETCH_HEAD", ".git/ORIG_HEAD",
                     ".git/packed-refs", ".git/info/refs", ".git/logs/HEAD"]
        
        # Add common branch refs
        for branch in ["main", "master", "staging", "production", "development"]:
            ref_files.extend([
                f".git/refs/heads/{branch}",
                f".git/logs/refs/heads/{branch}",
                f".git/refs/remotes/origin/{branch}",
                f".git/logs/refs/remotes/origin/{branch}",
            ])
        
        # Process refs to discover more
        pending_refs = deque(ref_files)
        processed_refs = set()
        
        while pending_refs:
            batch = [pending_refs.popleft() for _ in range(min(self.jobs, len(pending_refs)))]
            results = await asyncio.gather(*[self.find_refs(p) for p in batch if p not in processed_refs])
            
            for r in results:
                for ref in r:
                    if ref not in processed_refs:
                        pending_refs.append(ref)
                        processed_refs.add(ref)
        
        # Find and download pack files
        pack_path = os.path.join(self.directory, ".git", "objects", "info", "packs")
        if os.path.exists(pack_path):
            with open(pack_path, "r") as f:
                content = f.read()
            for sha1 in re.findall(r"pack-([a-f0-9]{40})\.pack", content):
                await self.download_file(f".git/objects/pack/pack-{sha1}.idx")
                await self.download_file(f".git/objects/pack/pack-{sha1}.pack")
        
        # Find objects from refs
        obj_tasks = set()
        for dirpath, _, filenames in os.walk(os.path.join(self.directory, ".git", "refs")):
            for filename in filenames:
                fpath = os.path.join(dirpath, filename)
                if os.path.exists(fpath):
                    with open(fpath, "r") as f:
                        content = f.read()
                    for obj in re.findall(r"(^|\s)([a-f0-9]{40})($|\s)", content):
                        obj_tasks.add(obj[1])
        
        # Also check logs
        for dirpath, _, filenames in os.walk(os.path.join(self.directory, ".git", "logs")):
            for filename in filenames:
                fpath = os.path.join(dirpath, filename)
                if os.path.exists(fpath):
                    with open(fpath, "r") as f:
                        content = f.read()
                    for obj in re.findall(r"(^|\s)([a-f0-9]{40})($|\s)", content):
                        obj_tasks.add(obj[1])
        
        # Fetch objects in parallel
        printf(f"[-] Fetching {len(obj_tasks)} objects...")
        await asyncio.gather(*[self.find_objects(o) for o in obj_tasks])
        
        # Checkout
        os.chdir(self.directory)
        sanitize_file(".git/config")
        
        import subprocess
        proc = subprocess.run(["git", "checkout", "."], capture_output=True)
        if proc.returncode != 0:
            log.warning("git checkout had issues")
        
        return True

    async def run(self):
        """Main execution."""
        os.makedirs(self.directory, exist_ok=True)
        self.normalize_url()
        
        if not await self.check_git_head():
            return 1
        
        # Check for directory listing
        try:
            response = await self.fetch(".git/")
            if response.status == 200 and is_html(response):
                files = get_indexed_files(response)
                if "HEAD" in files:
                    return await self.dump_directory_listing()
        except Exception:
            pass
        
        return await self.dump_sequential()


def main():
    """Entry point."""
    parser = argparse.ArgumentParser(
        usage="gitsiphon [options] URL DIR",
        description="Dump a git repository from a web server.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", help="Base URL of the git repository")
    parser.add_argument("directory", help="Output directory")
    parser.add_argument("--proxy", help="HTTP/SOCKS proxy (e.g., socks5://host:port)")
    parser.add_argument("--client-cert-p12", help="PKCS#12 client certificate")
    parser.add_argument("--client-cert-p12-password", help="Certificate password")
    parser.add_argument("-j", "--jobs", type=int, default=50,
                        help="Concurrent requests (default: 50)")
    parser.add_argument("-r", "--retry", type=int, default=3,
                        help="Retry attempts (default: 3)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("-u", "--user-agent", type=str,
                        help="Custom user-agent")
    parser.add_argument("-H", "--header", action="append",
                        help="Additional headers (NAME=VALUE)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Handle proxy
    if args.proxy:
        proxy_valid = False
        for pattern, proxy_type in [
            (r"^socks5://(.*):(\d+)$", socks.PROXY_TYPE_SOCKS5),
            (r"^socks4://(.*):(\d+)$", socks.PROXY_TYPE_SOCKS4),
            (r"^http://(.*):(\d+)$", socks.PROXY_TYPE_HTTP),
        ]:
            m = re.match(pattern, args.proxy)
            if m:
                socks.setdefaultproxy(proxy_type, m.group(1), int(m.group(2)))
                socket.socket = socks.socksocket
                proxy_valid = True
                break
        if not proxy_valid:
            parser.error(f"Invalid proxy format: {args.proxy}")
    
    # Client cert validation
    if args.client_cert_p12:
        if not os.path.exists(args.client_cert_p12):
            parser.error(f"Certificate not found: {args.client_cert_p12}")
        if args.client_cert_p12_password is None:
            parser.error("Certificate password required")
    
    # Run async
    dumper = GitSiphon(
        url=args.url,
        directory=args.directory,
        jobs=args.jobs,
        retry=args.retry,
        timeout=args.timeout,
        user_agent=args.user_agent,
        headers=args.header,
        proxy=args.proxy,
        client_cert=args.client_cert_p12,
        client_cert_password=args.client_cert_p12_password,
    )
    
    try:
        asyncio.run(dumper.run())
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
    finally:
        asyncio.run(dumper.close())
    
    log.success(f"Dump complete! Output: {args.directory}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

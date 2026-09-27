# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import time
import requests
import argparse
import logging
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

# How the bridge looks for Ghidra windows that were started without a matching --ghidra-server
# entry. The probe is bounded, so startup stays fast even when nothing is listening.
DEFAULT_SCAN_PORTS = "8080-8090"
MAX_SCANNED_PORTS = 64
DISCOVERY_TIMEOUT = 0.5

# The line /info answers that identifies a GhidraMCP server; a port is only registered when the
# probe sees it, so an unrelated service on the same range is never mistaken for one.
SERVICE_FINGERPRINT = "service=ghidra-mcp"

@dataclass(frozen=True)
class GhidraInstance:
    """
    One Ghidra window running the GhidraMCP plugin.

    Explicitly configured URLs are registered without a version and zero programs; the values
    are filled in from /info as soon as the plugin answers one.
    """
    id: str
    url: str
    version: str = ""
    programs: int = 0
    current_program: str = None

# Request tuning; all of these can be overridden from the command line (see main()).
REQUEST_TIMEOUT = 30.0
MAX_RETRIES = 2
RETRY_BACKOFF_SECONDS = 0.5

# Marks failures that happened before the Ghidra plugin could answer.
ERROR_PREFIX = "[bridge]"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

# Instances the bridge can address. discover_instances() rebuilds this list: the explicitly
# configured URLs come first, so the default target stays deterministic, then the ports the
# probe found, in ascending order.
_instances: list[GhidraInstance] = []
_explicit_urls: list[str] = [DEFAULT_GHIDRA_SERVER]
_scan_ports_spec = DEFAULT_SCAN_PORTS
_no_discovery = False
_discovery_timeout = DISCOVERY_TIMEOUT

class UnknownInstanceError(LookupError):
    """Raised when a call names an instance the registry does not know."""

def _normalize_base_url(url: str) -> str:
    """Return a base URL with a scheme and a trailing slash, the form the registry stores."""
    base = (url or "").strip()
    if not base:
        return ""
    if "://" not in base:
        base = "http://" + base
    return base if base.endswith("/") else base + "/"

def _instance_id(url: str) -> str:
    """Ids are derived from the port, falling back to the host for URLs without one."""
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        port = None
    return f"ghidra-{port}" if port else f"ghidra-{parsed.hostname or url}"

def _parse_info(body: str) -> dict:
    """Parse the key=value lines of /info into a dictionary."""
    info = {}
    for line in body.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            info[key.strip()] = value.strip()
    return info

def _probe_info(base_url: str) -> dict | None:
    """
    Ask a base URL for its /info, returning the payload only when the answer really comes from
    a GhidraMCP server. A refused connection, a timeout or an unrelated service is a miss.
    """
    try:
        response = requests.get(urljoin(base_url, "info"), timeout=_discovery_timeout)
    except requests.RequestException as e:
        logger.debug(f"Probe of {base_url} failed: {e}")
        return None
    if not response.ok:
        logger.debug(f"Probe of {base_url} returned HTTP {response.status_code}")
        return None
    response.encoding = "utf-8"
    if SERVICE_FINGERPRINT not in response.text:
        logger.debug(f"Probe of {base_url} is not a GhidraMCP server")
        return None
    return _parse_info(response.text)

def _instance_from_info(base_url: str, info: dict) -> GhidraInstance:
    """Turn a probed /info payload into a registry entry."""
    programs = info.get("programs", "")
    current = info.get("current") or None
    return GhidraInstance(
        id=_instance_id(base_url),
        url=base_url,
        version=info.get("version", ""),
        programs=int(programs) if programs.isdigit() else 0,
        current_program=None if current in (None, "(none)") else current,
    )

def _port_candidates() -> list[int]:
    """Expand --scan-ports ("8080-8090", "8081" or a comma-separated mix) into a port list."""
    ports: list[int] = []
    for part in _scan_ports_spec.split(","):
        part = part.strip()
        if not part:
            continue
        first, separator, last = part.partition("-")
        try:
            if separator:
                start, end = int(first), int(last)
            else:
                start = end = int(first)
        except ValueError:
            logger.warning(f"Ignoring invalid --scan-ports entry '{part}'")
            continue
        for port in range(start, end + 1):
            if len(ports) >= MAX_SCANNED_PORTS:
                logger.debug(f"Stopping the scan after {MAX_SCANNED_PORTS} ports")
                return ports
            if 0 < port < 65536:
                ports.append(port)
    return ports

def discover_instances() -> None:
    """
    Rebuild the registry: the explicit --ghidra-server URLs first (always registered, and
    /info stays optional so an older plugin keeps working), then the probed ports that answer
    with the GhidraMCP fingerprint.
    """
    global _instances
    discovered: list[GhidraInstance] = []
    seen: set[str] = set()

    for base_url in _explicit_urls:
        if not base_url or base_url in seen:
            continue
        seen.add(base_url)
        info = _probe_info(base_url)
        discovered.append(_instance_from_info(base_url, info) if info
                          else GhidraInstance(id=_instance_id(base_url), url=base_url))

    if not _no_discovery:
        for port in _port_candidates():
            base_url = f"http://127.0.0.1:{port}/"
            if base_url in seen:
                continue
            info = _probe_info(base_url)
            if info is None:
                continue
            seen.add(base_url)
            discovered.append(_instance_from_info(base_url, info))

    _instances = discovered

def refresh_instances() -> None:
    """
    Re-probe the configured sources, keeping instances that were known before, so a Ghidra
    window started after the bridge is picked up without restarting the bridge.
    """
    known = list(_instances)
    discover_instances()
    for instance in known:
        if all(existing.url != instance.url for existing in _instances):
            _instances.append(instance)

def _find_instance(target: str) -> GhidraInstance | None:
    """Match a target against the ids, URLs and bare ports of the known instances."""
    wanted = (target or "").strip()
    if not wanted:
        return None
    for instance in _instances:
        if wanted in (instance.id, instance.url, _normalize_base_url(instance.url)):
            return instance
    normalized = _normalize_base_url(wanted)
    for instance in _instances:
        if normalized == _normalize_base_url(instance.url):
            return instance
    if wanted.isdigit():
        return _find_instance(f"ghidra-{wanted}")
    return None

def resolve_instance(target: str | None) -> GhidraInstance | None:
    """
    Resolve an instance argument to a known instance.

    Args:
        target: an id ("ghidra-8081"), a base URL or a bare port; None means the default
                instance, which is the first explicit URL, else the lowest probed port.

    Returns:
        The instance, or None when the target is unknown (one re-discovery runs first).
    """
    if target is None or str(target).strip() == "":
        if not _instances:
            refresh_instances()
        return _instances[0] if _instances else None

    instance = _find_instance(str(target))
    if instance is None:
        refresh_instances()
        instance = _find_instance(str(target))
    return instance

def _unknown_instance_message(target: str | None) -> str:
    """Error text naming what the bridge does know, in the [bridge] error convention."""
    if target is None or str(target).strip() == "":
        return ("Request failed: no Ghidra instance is reachable "
                "(use --ghidra-server or --scan-ports)")
    known = ", ".join(instance.id for instance in _instances) or "none"
    return (f"Request failed: no Ghidra instance matched '{target}'; known instances: {known} "
            f"(use --ghidra-server or --scan-ports)")

def _resolve_target(target) -> GhidraInstance:
    """Accept an already resolved instance, or resolve a target, or explain why it failed."""
    instance = target if isinstance(target, GhidraInstance) else resolve_instance(target)
    if instance is None:
        raise UnknownInstanceError(_unknown_instance_message(target))
    return instance

def _endpoint_url(endpoint: str, instance: GhidraInstance = None) -> str:
    """
    Build the URL of an endpoint, by default on the configured Ghidra server.

    A base URL without a trailing slash would otherwise lose its last path segment when
    joined, so one is appended explicitly.
    """
    base = instance.url if instance is not None else ghidra_server_url
    base = base if base.endswith("/") else base + "/"
    return urljoin(base, endpoint.lstrip("/"))

def _request(method: str, endpoint: str, params: dict = None, data=None,
             instance=None, program: str = None) -> requests.Response:
    """
    Send a single request to one Ghidra instance, retrying connection-level failures only.

    `instance` may be a resolved instance or a target string (id, URL or bare port); a target
    the registry does not know raises UnknownInstanceError. `program` is always sent as a query
    parameter, never inside the body, so /decompile keeps using its raw body as the function
    name.

    HTTP error responses are returned untouched: they carry the plugin's own explanation
    and are never retried.
    """
    resolved = _resolve_target(instance)
    url = _endpoint_url(endpoint, resolved)
    if program:
        params = dict(params or {})
        params["program"] = program
    if isinstance(data, str):
        data = data.encode("utf-8")

    attempts = max(0, MAX_RETRIES) + 1
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            response = requests.request(method, url, params=params, data=data,
                                        timeout=REQUEST_TIMEOUT)
            response.encoding = 'utf-8'
            return response
        except (requests.ConnectionError, requests.Timeout) as e:
            last_error = e
            if attempt < attempts:
                logger.debug(f"{method} {url} failed ({e}); retrying {attempt}/{attempts - 1}")
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
    raise last_error

def _failure_message(e: Exception) -> str:
    """
    Render a request failure. An unknown target is reported with what the bridge knows,
    everything else keeps the plain connection error.
    """
    if isinstance(e, UnknownInstanceError):
        return f"{ERROR_PREFIX} {e}"
    return f"{ERROR_PREFIX} Request failed: {str(e)}"

def safe_get(endpoint: str, params: dict = None, instance: str = None,
             program: str = None) -> list:
    """
    Perform a GET request with optional query parameters, optionally on a chosen instance and
    for a chosen program.
    """
    if params is None:
        params = {}

    try:
        response = _request("GET", endpoint, params=params, instance=instance, program=program)
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [_failure_message(e)]

def safe_post(endpoint: str, data: dict | str, instance: str = None,
              program: str = None) -> str:
    try:
        response = _request("POST", endpoint, data=data, instance=instance, program=program)
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return _failure_message(e)

def _address_params(address: str = None, offset: str = None, block: str = None) -> dict:
    """
    Build the addressing query parameters, forwarding only the values that were supplied.
    """
    params = {}
    if address:
        params["address"] = address
    if offset:
        params["offset"] = offset
    if block:
        params["block"] = block
    return params

def _drop_none(params: dict) -> dict:
    """
    Drop keys whose value is None so an omitted argument is never sent as "address=None".
    """
    return {key: value for key, value in params.items() if value is not None}

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100, instance: str = None,
                 program: str = None) -> list:
    """
    List all function names in the program with pagination.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_get("methods", {"offset": offset, "limit": limit},
                    instance=instance, program=program)

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100, instance: str = None,
                 program: str = None) -> list:
    """
    List all namespace/class names in the program with pagination.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_get("classes", {"offset": offset, "limit": limit},
                    instance=instance, program=program)

@mcp.tool()
def decompile_function(name: str, instance: str = None, program: str = None) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_post("decompile", name, instance=instance, program=program)

@mcp.tool()
def rename_function(old_name: str, new_name: str, instance: str = None,
                    program: str = None) -> str:
    """
    Rename a function by its current name to a new user-defined name.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name},
                     instance=instance, program=program)

@mcp.tool()
def rename_data(address: str, new_name: str, instance: str = None,
                program: str = None) -> str:
    """
    Rename a data label at the specified address.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_post("renameData", {"address": address, "newName": new_name},
                     instance=instance, program=program)

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100, instance: str = None,
                  program: str = None) -> list:
    """
    List all memory segments in the program with pagination.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_get("segments", {"offset": offset, "limit": limit},
                    instance=instance, program=program)

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100, instance: str = None,
                 program: str = None) -> list:
    """
    List imported symbols in the program with pagination.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_get("imports", {"offset": offset, "limit": limit},
                    instance=instance, program=program)

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100, instance: str = None,
                 program: str = None) -> list:
    """
    List exported functions/symbols with pagination.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_get("exports", {"offset": offset, "limit": limit},
                    instance=instance, program=program)

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100, instance: str = None,
                    program: str = None) -> list:
    """
    List all non-global namespaces in the program with pagination.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit},
                    instance=instance, program=program)

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100, instance: str = None,
                    program: str = None) -> list:
    """
    List defined data labels and their values with pagination.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_get("data", {"offset": offset, "limit": limit},
                    instance=instance, program=program)

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100,
                             instance: str = None, program: str = None) -> list:
    """
    Search for functions whose name contains the given substring.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit},
                    instance=instance, program=program)

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str, instance: str = None,
                    program: str = None) -> str:
    """
    Rename a local variable within a function.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    }, instance=instance, program=program)

@mcp.tool()
def get_function_by_address(address: str, instance: str = None, program: str = None) -> str:
    """
    Get a function by its address.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address},
                              instance=instance, program=program))

@mcp.tool()
def get_current_address(instance: str = None, program: str = None) -> str:
    """
    Get the address currently selected by the user.

    `instance` selects the Ghidra window; `program` is ignored here, because this always
    describes the program the user is looking at.
    """
    return "\n".join(safe_get("get_current_address", instance=instance))

@mcp.tool()
def get_current_function(instance: str = None, program: str = None) -> str:
    """
    Get the function currently selected by the user.

    `instance` selects the Ghidra window; `program` is ignored here, because this always
    describes the program the user is looking at.
    """
    return "\n".join(safe_get("get_current_function", instance=instance))

@mcp.tool()
def list_functions(instance: str = None, program: str = None) -> list:
    """
    List all functions in the database.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_get("list_functions", instance=instance, program=program)

@mcp.tool()
def decompile_function_by_address(address: str, instance: str = None,
                                  program: str = None) -> str:
    """
    Decompile a function at the given address.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return "\n".join(safe_get("decompile_function", {"address": address},
                              instance=instance, program=program))

@mcp.tool()
def disassemble_function(address: str, instance: str = None, program: str = None) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_get("disassemble_function", {"address": address},
                    instance=instance, program=program)

@mcp.tool()
def set_decompiler_comment(address: str, comment: str, instance: str = None,
                           program: str = None) -> str:
    """
    Set a comment for a given address in the function pseudocode.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment},
                     instance=instance, program=program)

@mcp.tool()
def set_disassembly_comment(address: str, comment: str, instance: str = None,
                            program: str = None) -> str:
    """
    Set a comment for a given address in the function disassembly.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment},
                     instance=instance, program=program)

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str, instance: str = None,
                               program: str = None) -> str:
    """
    Rename a function by its address.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_post("rename_function_by_address",
                     {"function_address": function_address, "new_name": new_name},
                     instance=instance, program=program)

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str, instance: str = None,
                           program: str = None) -> str:
    """
    Set a function's prototype.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_post("set_function_prototype",
                     {"function_address": function_address, "prototype": prototype},
                     instance=instance, program=program)

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str,
                            instance: str = None, program: str = None) -> str:
    """
    Set a local variable's type.

    `instance` and `program` select the Ghidra window and the open program to act on;
    both default to the bridge default instance and its current program.
    """
    return safe_post("set_local_variable_type",
                     {"function_address": function_address, "variable_name": variable_name,
                      "new_type": new_type},
                     instance=instance, program=program)

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, instance: str = None,
                 program: str = None) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit},
                    instance=instance, program=program)

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, instance: str = None,
                   program: str = None) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit},
                    instance=instance, program=program)

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, instance: str = None,
                       program: str = None) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit},
                    instance=instance, program=program)

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None,
                 instance: str = None, program: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params, instance=instance, program=program)

@mcp.tool()
def read_bytes(address: str = None, offset: str = None, block: str = None,
               length: int = 64, format: str = "hex", instance: str = None,
               program: str = None) -> list:
    """
    Read raw bytes from memory at a virtual address, a raw file offset, or a memory
    block name plus offset.

    Address precedence when several are supplied: address > block+offset > offset.

    Args:
        address: Virtual address, hex (e.g. "0x140001000") or decimal
        offset: Raw file offset inside the loaded binary (hex or decimal)
        block: Memory block name; combined with offset it is relative to the block start
        length: Number of bytes to read (default 64, clamped to 1..8192)
        format: "hex" (default, 16 bytes per line with an ASCII gutter) or "base64"
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        Header line with the resolved address/block and read counts, then the bytes.
        Reads past the end of a block return the readable bytes with a short read count.
    """
    params = _address_params(address, offset, block)
    params["length"] = length
    if format:
        params["format"] = format
    return safe_get("read_bytes", params, instance=instance, program=program)

@mcp.tool()
def read_data(address: str = None, offset: str = None, block: str = None, count: int = 1,
              instance: str = None, program: str = None) -> list:
    """
    Read the defined, typed data items starting at a virtual address, a raw file offset,
    or a memory block name plus offset.

    Address precedence when several are supplied: address > block+offset > offset.

    Args:
        address: Virtual address, hex (e.g. "0x140020000") or decimal
        offset: Raw file offset inside the loaded binary (hex or decimal)
        block: Memory block name; combined with offset it is relative to the block start
        count: Maximum number of consecutive data items to return (default 1, max 64)
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        One line per item: "<address>: <label> = <value> [<type>, <n> bytes]".
        When nothing is defined at the address the containing item is reported, or a
        message suggesting read_bytes for raw bytes.
    """
    params = _address_params(address, offset, block)
    params["count"] = count
    return safe_get("read_data", params, instance=instance, program=program)

@mcp.tool()
def read_string(address: str = None, offset: str = None, block: str = None,
                max_length: int = 256, encoding: str = "auto", instance: str = None,
                program: str = None) -> str:
    """
    Decode the C string at a virtual address, a raw file offset, or a memory block name
    plus offset.

    Address precedence when several are supplied: address > block+offset > offset.

    Args:
        address: Virtual address, hex (e.g. "0x140030000") or decimal
        offset: Raw file offset inside the loaded binary (hex or decimal)
        block: Memory block name; combined with offset it is relative to the block start
        max_length: Maximum number of bytes to scan (default 256, max 4096)
        encoding: "auto" (default) | "ascii" | "utf8" | "utf16le" | "utf16be";
                  "auto" honours the data type at the address, then detects UTF-16 by
                  interleaved zero bytes, and otherwise falls back to ASCII/UTF-8
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        One line: "<address>: \\"<escaped value>\\" (<byte length> bytes, <encoding>)".
    """
    params = _address_params(address, offset, block)
    params["max_length"] = max_length
    if encoding:
        params["encoding"] = encoding
    return "\n".join(safe_get("read_string", params, instance=instance, program=program))

@mcp.tool()
def read_pointer(address: str = None, offset: str = None, block: str = None,
                 size: int = None, follow: bool = False, instance: str = None,
                 program: str = None) -> str:
    """
    Read a pointer-sized value at a virtual address, a raw file offset, or a memory
    block name plus offset, and optionally follow it.

    Address precedence when several are supplied: address > block+offset > offset.

    Args:
        address: Virtual address, hex (e.g. "0x140021000") or decimal
        offset: Raw file offset inside the loaded binary (hex or decimal)
        block: Memory block name; combined with offset it is relative to the block start
        size: Pointer size in bytes ("4" or "8"); defaults to the program pointer size
        follow: When True, also report the data at the target, or a 16-byte hex dump
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        "<address>: <raw bytes> -> <target> (<symbol or unnamed>, block <name>)",
        plus target detail lines when follow is True.
    """
    params = _address_params(address, offset, block)
    if size is not None:
        params["size"] = size
    if follow:
        params["follow"] = "true"
    return "\n".join(safe_get("read_pointer", params, instance=instance, program=program))

@mcp.tool()
def get_function_details(address: str = None, name: str = None, instance: str = None,
                         program: str = None) -> str:
    """
    Describe one function: signature, calling convention, return type, stack frame, flags,
    body range and immediate caller/callee counts.

    Supply `address` (the function at or containing it) or `name` (an exact function name);
    `address` wins when both are given.

    Args:
        address: Address inside the function, hex (e.g. "0x140001000") or decimal
        name: Exact function name
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        Key/value lines: name, entry, signature, calling convention, return type, parameter
        count, stack frame size, body range, flags and immediate caller/callee counts.
    """
    return "\n".join(safe_get("get_function_details",
                              _drop_none({"address": address, "name": name}),
                              instance=instance, program=program))

@mcp.tool()
def list_function_variables(address: str = None, name: str = None, offset: int = 0,
                            limit: int = 100, instance: str = None,
                            program: str = None) -> list:
    """
    List the parameters and local variables of one function, with type, size and storage.

    Args:
        address: Address inside the function, hex (e.g. "0x140001000") or decimal
        name: Exact function name
        offset: Number of variables to skip (default 0)
        limit: Maximum number of variables to return (default 100, max 1000)
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        One line per variable: "<param|local> <name> : <type> (<n> bytes) [<storage>] @ <address>";
        auto-parameters are marked with "(auto)". The last line is the "# showing X-Y of N"
        summary of the listing.
    """
    return safe_get("list_function_variables",
                    _drop_none({"address": address, "name": name,
                                "offset": offset, "limit": limit}),
                    instance=instance, program=program)

@mcp.tool()
def get_comments(address: str = None, name: str = None, scope: str = None, offset: int = 0,
                 limit: int = 200, instance: str = None, program: str = None) -> list:
    """
    Read the comments stored at one address or anywhere inside a function.

    Args:
        address: Address to read, or a function containing it, hex or decimal
        name: Exact function name; when given, the scope defaults to the function body
        scope: "address" or "function"; default: address when only `address` is given,
               function when `name` is given
        offset: Number of commented code units to skip (function scope, default 0)
        limit: Maximum number of commented code units (function scope, default 200, max 1000)
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        Address scope: "<address>:" followed by one indented "PRE|EOL|PLATE|POST: <text>" line
        per comment present. Function scope: such a block per commented code unit, followed by
        the "# showing X-Y of N" summary.
    """
    return safe_get("get_comments",
                    _drop_none({"address": address, "name": name, "scope": scope,
                                "offset": offset, "limit": limit}),
                    instance=instance, program=program)

@mcp.tool()
def list_data_types(filter: str = None, offset: int = 0, limit: int = 100, instance: str = None,
                    program: str = None) -> list:
    """
    List the data types the program knows, with their kind and size.

    Args:
        filter: Case-insensitive substring matched against the type name or full path
        offset: Number of data types to skip (default 0)
        limit: Maximum number of data types to return (default 100, max 1000)
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        One line per type: "<path> (<kind>, <n> bytes)" with kind one of struct, union, enum,
        typedef, pointer, array, function or builtin, followed by the "# showing X-Y of N"
        summary of the listing.
    """
    return safe_get("list_data_types",
                    _drop_none({"filter": filter, "offset": offset, "limit": limit}),
                    instance=instance, program=program)

@mcp.tool()
def get_data_type(name: str, instance: str = None, program: str = None) -> str:
    """
    Describe one data type: the fields of a struct/union, the members of an enum, the target of
    a typedef, or the size and description of a simple type.

    Args:
        name: Simple type name or full path (e.g. "VECTOR3" or "/user/vector.h/VECTOR3")
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        Name/kind/size/path header plus the kind-specific body. An unknown name answers
        "Data type not found: '<name>'"; a name matching several types lists the candidates.
    """
    return "\n".join(safe_get("get_data_type", {"name": name},
                              instance=instance, program=program))

@mcp.tool()
def get_callers(address: str = None, name: str = None, depth: int = 1, offset: int = 0,
                limit: int = 100, instance: str = None, program: str = None) -> list:
    """
    Walk the call graph upwards: the functions that reach this one, level by level.

    Args:
        address: Address inside the function, hex (e.g. "0x140001000") or decimal
        name: Exact function name
        depth: Traversal depth, clamped to 1..4 (default 1)
        offset: Number of lines to skip (default 0)
        limit: Maximum number of lines to return (default 100, max 1000)
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        One line per caller: "d<depth> <address> <name> (caller of <previous name>)", followed
        by the "# showing X-Y of N" summary. A function appears once, at the shallowest depth
        it is reachable at, so mutual recursion does not loop.
    """
    return safe_get("get_callers",
                    _drop_none({"address": address, "name": name, "depth": depth,
                                "offset": offset, "limit": limit}),
                    instance=instance, program=program)

@mcp.tool()
def get_callees(address: str = None, name: str = None, depth: int = 1, offset: int = 0,
                limit: int = 100, instance: str = None, program: str = None) -> list:
    """
    Walk the call graph downwards: the functions this one reaches, level by level.

    Args:
        address: Address inside the function, hex (e.g. "0x140001000") or decimal
        name: Exact function name
        depth: Traversal depth, clamped to 1..4 (default 1)
        offset: Number of lines to skip (default 0)
        limit: Maximum number of lines to return (default 100, max 1000)
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        One line per callee: "d<depth> <address> <name> (callee of <previous name>)", followed
        by the "# showing X-Y of N" summary.
    """
    return safe_get("get_callees",
                    _drop_none({"address": address, "name": name, "depth": depth,
                                "offset": offset, "limit": limit}),
                    instance=instance, program=program)

@mcp.tool()
def search_bytes(pattern: str, block: str = None, offset: int = 0, limit: int = 100,
                 instance: str = None, program: str = None) -> list:
    """
    Search initialized memory for a hex byte pattern; '??' matches any single byte.

    Args:
        pattern: Whitespace-separated pattern, e.g. "48 8B ?? 40"; max 256 bytes
        block: Restrict the scan to one memory block by name (e.g. ".text")
        offset: Number of matches to skip (default 0)
        limit: Maximum number of matches to return (default 100, max 5000)
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        One line per match: "0x<address> in <block> (<containing function>): <actual bytes>",
        followed by the "# showing X-Y of N" summary. The scan stops as soon as the requested
        page is full, so a full page means more matches may follow.
    """
    return safe_get("search_bytes",
                    _drop_none({"pattern": pattern, "block": block,
                                "offset": offset, "limit": limit}),
                    instance=instance, program=program)

@mcp.tool()
def search_symbols(query: str, kind: str = "any", case_sensitive: bool = False, offset: int = 0,
                   limit: int = 100, instance: str = None, program: str = None) -> list:
    """
    Search function, label and data symbol names with a regular expression.

    Args:
        query: Regular expression, e.g. "FUN_.*10$" (not anchored, so it matches anywhere)
        kind: "any" (default), "function", "label" or "data"
        case_sensitive: Match case-sensitively (default false)
        offset: Number of matches to skip (default 0)
        limit: Maximum number of matches to return (default 100, max 1000)
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        One line per match: "<name> <kind> @ <address>", with the namespace-qualified name when
        there is one, followed by the "# showing X-Y of N" summary. An invalid regex answers
        "Invalid regular expression: <message>".
    """
    return safe_get("search_symbols",
                    _drop_none({"query": query, "kind": kind,
                                "case_sensitive": "true" if case_sensitive else None,
                                "offset": offset, "limit": limit}),
                    instance=instance, program=program)

@mcp.tool()
def get_program_info(offset: int = 0, limit: int = 100, instance: str = None,
                     program: str = None) -> str:
    """
    Describe the loaded program: language, compiler, endianness, image base, address range,
    counts and the external entry points. Recommended as the first call on a new program.

    Args:
        offset: Number of entry points to skip (default 0)
        limit: Maximum number of entry points to return (default 100, max 1000)
        instance: Target Ghidra instance (id, base URL or port); default: the first one
        program: Open program in that instance; default: its current program

    Returns:
        Key/value lines for name, file, language, compiler, endianness, address size, image
        base, address range, memory blocks, functions, symbols, defined data, executable
        format and MD5, then "Entry points:" with one "  0x<address> <label>" line per entry
        point and the "# showing X-Y of N" summary.
    """
    return "\n".join(safe_get("get_program_info", {"offset": offset, "limit": limit},
                              instance=instance, program=program))

@mcp.tool()
def list_instances(rescan: bool = False) -> list:
    """
    List the GhidraMCP instances the bridge can talk to.

    Args:
        rescan: Re-run discovery first, so windows started after the bridge are picked up

    Returns:
        One line per instance: "<id> | <url> | v<version> | current: <program> | programs: <n>".
        The id (or the URL, or the bare port) is what the `instance` argument of the other
        tools accepts.
    """
    if rescan:
        refresh_instances()
    elif not _instances:
        refresh_instances()
    if not _instances:
        return [f"{ERROR_PREFIX} Request failed: no Ghidra instance is reachable "
                f"(use --ghidra-server or --scan-ports)"]
    return [f"{instance.id} | {instance.url} | v{instance.version or 'unknown'} | "
            f"current: {instance.current_program or '(none)'} | programs: {instance.programs}"
            for instance in _instances]

@mcp.tool()
def list_open_programs(instance: str = None) -> list:
    """
    List the programs open in one Ghidra instance.

    Args:
        instance: Target instance: an id ("ghidra-8081"), a base URL or a bare port
                  ("8081"); default: the first configured instance

    Returns:
        One line per open program: "<name> | <path> | <language id> | <current|open>".
        The name can then be passed as `program` to any other tool.
    """
    return safe_get("list_open_programs", instance=instance)

def main():
    global ghidra_server_url, REQUEST_TIMEOUT, MAX_RETRIES
    global _explicit_urls, _scan_ports_spec, _no_discovery, _discovery_timeout
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, action="append", default=None,
                        help="Base URL of a GhidraMCP server; repeat the flag or separate the "
                             f"URLs with commas, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--scan-ports", type=str, default=DEFAULT_SCAN_PORTS,
                        help="Localhost port or range to probe for GhidraMCP servers; a port is "
                             f"only used when /info identifies one, default: {DEFAULT_SCAN_PORTS}")
    parser.add_argument("--no-discovery", action="store_true",
                        help="Do not probe --scan-ports; only the --ghidra-server URLs are used")
    parser.add_argument("--discovery-timeout", type=float, default=DISCOVERY_TIMEOUT,
                        help="Seconds to wait for each probed port, "
                             f"default: {DISCOVERY_TIMEOUT:g}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    parser.add_argument("--request-timeout", type=float, default=REQUEST_TIMEOUT,
                        help="Seconds to wait for the Ghidra plugin to answer; large "
                             f"decompilations need a generous value, default: {REQUEST_TIMEOUT:g}")
    parser.add_argument("--retries", type=int, default=MAX_RETRIES,
                        help="Retries for connection-level failures; HTTP errors are never "
                             f"retried, default: {MAX_RETRIES}")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level, default: INFO")
    args = parser.parse_args()

    # Use the global variables to ensure they're properly updated
    urls = []
    for value in args.ghidra_server or []:
        urls.extend(_normalize_base_url(part) for part in value.split(","))
    _explicit_urls = [url for url in urls if url] or [DEFAULT_GHIDRA_SERVER]
    _scan_ports_spec = args.scan_ports
    _no_discovery = args.no_discovery
    _discovery_timeout = args.discovery_timeout
    ghidra_server_url = _explicit_urls[0]
    REQUEST_TIMEOUT = args.request_timeout
    MAX_RETRIES = args.retries

    log_level = getattr(logging, args.log_level)
    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
    logger.info(f"Request timeout: {REQUEST_TIMEOUT:g}s, retries: {MAX_RETRIES}")

    discover_instances()
    if _no_discovery:
        logger.info("Port discovery is disabled; only --ghidra-server URLs are registered")
    for instance in _instances:
        logger.info(f"Ghidra instance {instance.id} at {instance.url}"
                    + (f" (version {instance.version})" if instance.version else ""))
    if not _instances:
        logger.warning("No Ghidra instance found; use --ghidra-server or --scan-ports")

    if args.transport == "sse":
        try:
            # Configure MCP settings
            mcp.settings.log_level = args.log_level
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()


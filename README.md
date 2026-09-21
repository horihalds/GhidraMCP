[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# ghidraMCP
ghidraMCP is an Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports
- Read raw bytes, typed data, strings and pointers at virtual addresses, file offsets, or memory block offsets
- Introspect a function's real signature, calling convention, parameters and locals
- Inspect struct, union, enum and typedef layouts, and read back existing comments
- Walk callers and callees to a bounded depth in one call
- Search memory for hex signatures with `??` wildcards and find symbols with regular expressions
- Summarise a program's language, compiler, layout, counts and entry points in one call
- Every listing ends with a "# showing X-Y of N" total so pagination is predictable
- Work across several Ghidra windows and all of their open programs in one session
- Configurable request timeout, retries and logging in the MCP bridge

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-2.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
7. *Optional*: Configure the port in Ghidra with `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP.  Three examples are given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

The server IP and port are configurable and should be set to point to the target Ghidra instance. If not set, both will default to localhost:8080.

## Example 2: Cline
To use GhidraMCP with [Cline](https://cline.bot), this requires manually running the MCP server as well. First run the following command:

```
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

The only *required* argument is the transport. If all other arguments are unspecified, they will default to the above. Once the MCP server is running, open up Cline and select `MCP Servers` at the top.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

Then select `Remote Servers` and add the following, ensuring that the url matches the MCP host and port:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8081/sse`

## Example 3: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

## Bridge options
`bridge_mcp_ghidra.py` accepts the following flags; all of them are optional:

| Flag | Default | Description |
|---|---|---|
| `--ghidra-server` | `http://127.0.0.1:8080/` | Base URL of a GhidraMCP server; repeat the flag or separate the URLs with commas, e.g. `--ghidra-server http://127.0.0.1:8080/,http://127.0.0.1:8081/`. These URLs are registered as instances even when `/info` is unavailable |
| `--scan-ports` | `8080-8090` | Localhost port or range to probe for more GhidraMCP servers; a port is only registered when its `/info` answers with `service=ghidra-mcp`, so an unrelated local service is ignored |
| `--no-discovery` | off | Do not probe `--scan-ports`; only the `--ghidra-server` URLs are used |
| `--discovery-timeout` | `0.5` | Seconds to wait for each probed port |
| `--transport` | `stdio` | MCP transport (`stdio` or `sse`) |
| `--mcp-host` | `127.0.0.1` | Host to serve the SSE transport on |
| `--mcp-port` | `8081` | Port to serve the SSE transport on |
| `--request-timeout` | `30` | Seconds to wait for the plugin; raise it if very large functions time out |
| `--retries` | `2` | Retries for connection-level failures only, with a short backoff; HTTP errors are never retried |
| `--log-level` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

If the plugin cannot be reached at all, the tools return a `[bridge] Request failed: ...` line instead of raising, so the client sees why the call failed. HTTP errors keep the plugin's own body (`Error <status>: <body>`).

# Several Ghidra Instances
One bridge session can address several Ghidra windows and, inside each of them, every open program. Each known window is an *instance*: an explicit `--ghidra-server` URL or a port the probe found, identified as `ghidra-<port>`. Explicit URLs come first, so with no arguments the bridge still talks to `http://127.0.0.1:8080/` exactly as before.

Every tool accepts the same two optional arguments:

| Argument | Meaning |
|---|---|
| `instance` | the target window: an id (`ghidra-8081`), a base URL (`http://127.0.0.1:8081/`) or a bare port (`8081`); omit it for the first instance |
| `program` | the open program to act on in that window; forwarded to the plugin as the `program` parameter described below; omit it for that window's current program |

```python
decompile_function(name="main", instance="8081", program="libfoo.so")
list_functions(instance="ghidra-8082")     # program omitted -> that window's current program
```

`list_instances` shows what the bridge knows (pass `rescan=True` to look for windows started later), and `list_open_programs` shows what can be passed as `program`:

```
ghidra-8080 | http://127.0.0.1:8080/ | v12.1.3 | current: libfoo.so | programs: 2
ghidra-8081 | http://127.0.0.1:8081/ | v12.1.3 | current: bar.exe   | programs: 1
```

An unknown target is reported instead of guessed, listing what is known. The bridge also re-runs discovery once before failing, so a Ghidra window started after the bridge is picked up without restarting it. If nothing answers, the message names the flags that control discovery:

```
[bridge] Request failed: no Ghidra instance matched '8085'; known instances: ghidra-8080, ghidra-8081 (use --ghidra-server or --scan-ports)
```

Client configurations that use discovery or an explicit list:

```json
{"mcpServers": {"ghidra": {"command": "python", "args": ["/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py", "--scan-ports", "8080-8090"]}}}
```
```json
{"mcpServers": {"ghidra": {"command": "python", "args": ["/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py", "--ghidra-server", "http://127.0.0.1:8080/,http://127.0.0.1:8081/", "--no-discovery"]}}}
```
The SSE transport takes the same flags:

```
python bridge_mcp_ghidra.py --transport sse --scan-ports 8080-8090
```

# Selecting a Program
Every endpoint acts on the program the Ghidra tool currently shows. When more than one program is open, any endpoint also accepts an optional `program` parameter to act on one of the others:

```bash
curl "http://127.0.0.1:8080/decompile_function?address=0x140001000&program=libfoo.so"
curl -d "oldName=sub_401000&newName=login" "http://127.0.0.1:8081/renameFunction?program=bar.exe"
```

The value may be the program name, the domain-file name, a path suffix, or the literal `current` (the default). Matching tries the exact name first, then a case-insensitive name, then the file name, and finally a path suffix. An unknown or ambiguous selector is reported as plain text instead of a program being picked at random:

```
No program matching 'foo'. Open programs: libfoo.so, bar.exe
Ambiguous program 'bar': /proj/a/bar, /proj/b/bar
```

`GET /list_open_programs` lists what can be selected, one line per open program; `offset` (default `0`) and `limit` (default `100`) behave like the other listing endpoints:

```bash
curl "http://127.0.0.1:8080/list_open_programs"
```
```
libfoo.so | /proj/libfoo.so | x86:LE:64:default | current
bar.exe   | /proj/bar.exe   | x86:LE:32:default | open
```

The two endpoints that describe what is selected in the Ghidra UI, `/get_current_address` and `/get_current_function`, always answer for the tool's visible program and ignore `program` by design.

# Running Several Ghidra Windows
Every Ghidra window reads the same `Server Port` option, which defaults to `8080`. When that port is already bound, the plugin listens on the next free port within the following ten ports instead of failing to start, logs the port it uses, and leaves the option untouched; two windows therefore coexist without any manual configuration.

`GET /info` reports what the server is: the fingerprint, the extension version, the port it is actually bound to and the programs that are open:

```bash
curl "http://127.0.0.1:8081/info"
```
```
service=ghidra-mcp
version=12.1.3
port=8081
programs=1
current=bar.exe
```

The `service=ghidra-mcp` line is the fingerprint the bridge looks for when it probes a port range, and `port` may differ from the configured value.

# Listing Totals
Every paginated listing endpoint ends with a `#`-prefixed summary line, so a client can tell how much data exists and whether it has to request another page instead of guessing. This covers `/methods`, `/classes`, `/segments`, `/imports`, `/exports`, `/namespaces`, `/data`, `/strings`, the function-name search, the xref listings and `/list_open_programs`, as well as the newer listings.

```
libfoo.so | /proj/libfoo.so | x86:LE:64:default | current
bar.exe   | /proj/bar.exe   | x86:LE:32:default | open

# showing 1-2 of 2
```

- `# showing 1-100 of 4823` – the page contains items 1 to 100 of 4823
- `# showing 0 of 0` – the listing is empty
- `# showing 0 of 4823 (offset 5000)` – the requested `offset` is past the end, so no data lines follow

The summary is always the last line of the response body (and therefore the last element of a bridge tool's result list). Listings that keep a dedicated empty-state message, such as `No functions matching 'foo'`, print that message first and the summary right after it.

# Reading Memory
The bridge exposes four read-only tools (`read_bytes`, `read_data`, `read_string`, `read_pointer`) backed by the matching HTTP endpoints. Every endpoint accepts one of three addressing modes:

- `address` – virtual address, hex (`0x140001000`) or decimal
- `offset` – raw file offset inside the loaded binary
- `block` + `offset` – offset relative to the start of the named memory block

Precedence when several are supplied: `address` > `block`+`offset` > `offset`. Responses are plain text and include the resolved address, so an offset-based request can be mapped back to an address.

## `read_bytes`
Read raw bytes; `length` defaults to `64` (clamped to `1..8192`) and `format` is `hex` (default, 16 bytes per line with an ASCII gutter) or `base64`.

```bash
curl "http://127.0.0.1:8080/read_bytes?address=0x140001000&length=32"
curl "http://127.0.0.1:8080/read_bytes?offset=0x400&length=16"
curl "http://127.0.0.1:8080/read_bytes?block=.text&offset=0x10&format=base64"
```

## `read_data`
Read the defined, typed data items starting at the address; `count` defaults to `1` (max `64`). Each line is `<address>: <label> = <value> [<type>, <n> bytes]`; when nothing is defined at the address the containing item is reported.

```bash
curl "http://127.0.0.1:8080/read_data?address=0x140020000&count=3"
```

## `read_string`
Decode the C string at the address; `max_length` defaults to `256` (max `4096`) and `encoding` is `auto` (default), `ascii`, `utf8`, `utf16le` or `utf16be`. `auto` honours the data type at the address, detects UTF-16 by interleaved zero bytes, and otherwise falls back to ASCII/UTF-8.

```bash
curl "http://127.0.0.1:8080/read_string?address=0x140030000"
curl "http://127.0.0.1:8080/read_string?address=0x140030000&encoding=utf16le"
```

## `read_pointer`
Read a pointer-sized value, decoded using the program endianness; `size` defaults to the program pointer size (allowed `4` or `8`). `follow=true` additionally reports the typed data at the target, or a 16-byte hex dump when none is defined there.

```bash
curl "http://127.0.0.1:8080/read_pointer?address=0x140021000&follow=true"
```

Responses are UTF-8 plain text. Non-ASCII characters in listing and memory output (for example a non-ASCII symbol label) are escaped as full code units, e.g. `caf\xe9`; characters above `U+00FF` keep their whole value instead of being truncated to one byte.

# Function Introspection and Comments
Three read-only tools describe a function without decompiling it and let a client read back the comments an earlier analysis wrote. Every one of them accepts either `address` (an address at or inside the function) or `name` (an exact function name); `address` wins when both are given.

## `get_function_details`
Report the real declaration of a function instead of guessing it from the decompiled C:

```bash
curl "http://127.0.0.1:8080/get_function_details?address=0x140001000"
curl "http://127.0.0.1:8080/get_function_details?name=main"
```
```
Function: FUN_140001000
Entry: 0x140001000
Signature: int __cdecl FUN_140001000(int a, char * b)
Calling convention: __cdecl
Return type: int (4 bytes)
Parameters: 2
Stack frame: 16
Body: 0x140001000 - 0x1400010a3 (164 bytes)
Flags: thunk=false noReturn=false varArgs=false external=false inline=false
Callers: 3
Callees: 5
```

The caller/callee counts are immediate, i.e. one level; use `get_callers`/`get_callees` to walk further.

## `list_function_variables`
List the parameters and locals with their type, size, storage and the address of their first use. `offset` (default `0`) and `limit` (default `100`, max `1000`) paginate, and auto-parameters are marked so they are not renamed:

```bash
curl "http://127.0.0.1:8080/list_function_variables?name=main"
```
```
param a : int (4 bytes) [Stack[0x4]] @ 0x140001000
param (auto) __return_storage_ptr__ : void * (8 bytes) [RAX:8] @ 0x140001000
local local_10 : undefined4 (4 bytes) [Stack[-0x10]] @ 0x140001004

# showing 1-3 of 3
```

## `get_comments`
Read the `PRE`, `EOL`, `PLATE` and `POST` comments at one address (`scope=address`, the default when only `address` is given) or everywhere in a function body (`scope=function`, the default when `name` is given, also selectable explicitly):

```bash
curl "http://127.0.0.1:8080/get_comments?address=0x140001010"
curl "http://127.0.0.1:8080/get_comments?name=main&scope=function"
```
```
0x140001010:
  PRE: entry of the check
  EOL: compare flags
```

Function scope reports one block per commented code unit and paginates those blocks with `offset` (default `0`) and `limit` (default `200`, max `1000`), so a comment is never split from its address. An address with no comment answers `No comments at <address>:`; a function without any answers `No comments in function <name>` followed by the summary.

# Data Types
## `list_data_types`
Enumerate every data type the program knows, with its kind and size. `filter` is a case-insensitive substring matched against the type name or its full path; `offset` (default `0`) and `limit` (default `100`, max `1000`) paginate:

```bash
curl "http://127.0.0.1:8080/list_data_types?filter=vector"
```
```
/user/vector.h/VECTOR3 (struct, 12 bytes)
/eh/EHExceptionRecord (struct, 32 bytes)
char (builtin, 1 bytes)

# showing 1-3 of 412
```

The kind is one of `struct`, `union`, `enum`, `typedef`, `pointer`, `array`, `function` or `builtin`.

## `get_data_type`
Inspect one type by simple name or full path. Structures and unions print one line per field with offset, name, type and size, plus any field comment; enums print their member/value pairs; typedefs print the aliased type; simple types print their size and description:

```bash
curl "http://127.0.0.1:8080/get_data_type?name=VECTOR3"
curl "http://127.0.0.1:8080/get_data_type?name=/user/vector.h/VECTOR3"
```
```
Name: VECTOR3
Kind: struct
Size: 12
Path: /user/vector.h/VECTOR3
Fields: 3
+0x0    x : float (4)
+0x4    y : float (4)   // vertical component
+0x8    z : float (4)
```

An unknown name answers `Data type not found: '<name>'`. A name that matches several types in different categories answers `Data type 'x' is ambiguous; candidates:` followed by one `<path> (<kind>, <n> bytes)` line per candidate, so nothing is picked arbitrarily.

# Call Graph
## `get_callers` / `get_callees`
Traverse the call graph in one call instead of chaining xrefs. Both accept `address` or `name`, a `depth` clamped to `1..4` (default `1`) and the usual `offset` (default `0`) / `limit` (default `100`, max `1000`) pagination.

```bash
curl "http://127.0.0.1:8080/get_callers?name=FUN_140001000&depth=2"
curl "http://127.0.0.1:8080/get_callees?address=0x140001000&depth=2"
```
```
d1 0x140002100 FUN_140002100 (caller of FUN_140001000)
d2 0x140003000 FUN_140003000 (caller of FUN_140002100)

# showing 1-2 of 2
```

`get_callers` follows every reference to the function's entry point and attributes the referring address to the function that contains it; `get_callees` follows `getCalledFunctions`. Every line carries the depth (`d1`, `d2`, …), the function's entry point, its name and its relation to the previous level. A function is reported once, at the shallowest depth it is reachable at, so mutual recursion terminates instead of looping.

# Search
## `search_bytes`
Find a hex signature anywhere in initialized memory. `pattern` is whitespace-separated tokens, each either two hex digits or `??` for "any byte", and is capped at 256 bytes:

```bash
curl "http://127.0.0.1:8080/search_bytes?pattern=48%208b%20%3F%3F%2040"
curl "http://127.0.0.1:8080/search_bytes?pattern=7f%2045%204c%2046&block=.text"
```
```
0x140001234 in .text (FUN_140001200): 48 8b 05 40

# showing 1-1 of 1
```

- Uninitialized blocks are skipped, and the optional `block=<name>` narrows the scan to one block.
- `offset` (default `0`) and `limit` (default `100`, max `5000`) paginate the matches, and the scan stops as soon as the requested page is full, so an early page never walks the whole binary. A full page therefore means more matches may follow.
- Invalid patterns answer with a message naming the offending token, e.g. `Invalid byte pattern token 'xZ' (expected two hex digits or ??)`; a pattern longer than 256 bytes and an unknown `block` are reported the same way.
- Addresses are reported with the matched bytes in memory order, so they line up with `/read_bytes` for the same address.

## `search_symbols`
Search function, label and data names with a regular expression instead of a substring. The query is matched anywhere in the name and is case-insensitive unless `case_sensitive=true`:

```bash
curl "http://127.0.0.1:8080/search_symbols?query=FUN_.*10%24"
curl "http://127.0.0.1:8080/search_symbols?query=vector&kind=data"
```
```
FUN_140001000 function @ 0x140001000
my_global label @ 0x140100000

# showing 1-2 of 2
```

`kind` selects `any` (default), `function`, `label` (a symbol without defined data) or `data` (a symbol sitting on defined data). Names are namespace-qualified when they live in a namespace, e.g. `Foo::bar`. An invalid regular expression answers `Invalid regular expression: <message>` instead of failing the request.

# Program Information
## `get_program_info`
Recommended as the first call on a newly loaded program: one request reports the architecture, the compiler, the memory layout and the scale of the binary, so an analysis can be planned before any function is touched.

```bash
curl "http://127.0.0.1:8080/get_program_info"
```
```
Program: libfoo.so
File: /tmp/libfoo.so
Language: x86:LE:64:default
Compiler: gcc (gcc)
Endianness: little
Address size: 8
Image base: 0x140000000
Address range: 0x140000000 - 0x1400fffff
Memory blocks: 6
Functions: 4823
Symbols: 12034
Defined data: 2311
Executable format: ELF
Executable MD5: 9f2c5e1e5b9d4b0e8d3a6f2c8b7a1d4e
Entry points:
  0x140001000 on
  0x140002000 call_weak_fn

# showing 1-2 of 2
```

The counts match what `/methods`, `/data` and `/segments` report for the same program, so they can be used as cross-checks. `offset` (default `0`) and `limit` (default `100`, max `1000`) paginate only the entry-point list. Fields that the loaded format does not provide answer `unknown`.

# Development
The extension is split into small, single-responsibility packages:

```
src/main/java/com/lauriewired/
  GhidraMCPPlugin.java   plugin lifecycle only: tool option, server start/stop, dispose
  server/                embedded HTTP server: bootstrap, single route table, responses
  handlers/              one class per endpoint group: listing, xrefs, memory,
                         decompilation, mutations, prototypes, server metadata,
                         function introspection, comments, data types, call graph,
                         search, program info
  service/               shared Ghidra access: current program, Swing transactions,
                         decompiler reuse, address resolution, function lookup
  util/                  dependency-free helpers: query/body parsing, pagination,
                         escaping, byte patterns
```

Run the unit tests:

```bash
mvn -o test
```

The suites cover the dependency-free helpers in `util/` and pin the historical endpoint paths of the route table, so they need neither a Ghidra runtime nor a free network port. Compiling at all still requires the Ghidra jars listed below.

Build the installable extension:

```bash
mvn -o package
```

This produces `target/GhidraMCP.jar` and `target/GhidraMCP-1.0-SNAPSHOT.zip`.

# Building from Source
1. Copy the following files from your Ghidra directory to this project's `lib/` directory:
- `Ghidra/Features/Base/lib/Base.jar`
- `Ghidra/Features/Decompiler/lib/Decompiler.jar`
- `Ghidra/Framework/Docking/lib/Docking.jar`
- `Ghidra/Framework/Generic/lib/Generic.jar`
- `Ghidra/Framework/Project/lib/Project.jar`
- `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
- `Ghidra/Framework/Utility/lib/Utility.jar`
- `Ghidra/Framework/Gui/lib/Gui.jar`
2. Build with Maven by running:

`mvn clean package assembly:single`

The generated zip file includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.

- lib/GhidraMCP.jar
- extensions.properties
- Module.manifest

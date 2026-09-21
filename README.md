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

# Development
The extension is split into small, single-responsibility packages:

```
src/main/java/com/lauriewired/
  GhidraMCPPlugin.java   plugin lifecycle only: tool option, server start/stop, dispose
  server/                embedded HTTP server: bootstrap, single route table, responses
  handlers/              one class per endpoint group: listing, xrefs, memory,
                         decompilation, mutations, prototypes, server metadata
  service/               shared Ghidra access: current program, Swing transactions,
                         decompiler reuse, address resolution
  util/                  dependency-free helpers: query/body parsing, pagination, escaping
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

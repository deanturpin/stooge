# Wireshark Lua Dissectors

This directory contains Lua protocol dissectors compatible with Wireshark. These dissectors help analyse application-layer protocols in captured network traffic.

## Available Dissectors

- **http.lua** - HTTP request/response parser (ports 80, 8080, 443)
- **dns.lua** - DNS query/response parser (port 53, UDP/TCP)

## Using in Wireshark

### Option 1: User Plugin Directory

Copy dissector files to your Wireshark personal plugins directory:

**Linux/macOS:**

```bash
mkdir -p ~/.local/lib/wireshark/plugins
cp dissectors/*.lua ~/.local/lib/wireshark/plugins/
```

**Windows:**

```powershell
Copy-Item dissectors\*.lua "$env:APPDATA\Wireshark\plugins\"
```

### Option 2: Command Line

Load dissectors when launching Wireshark:

```bash
wireshark -X lua_script:dissectors/http.lua -X lua_script:dissectors/dns.lua
```

### Option 3: Global Plugins Directory

Copy to system-wide Wireshark plugins directory (requires admin/root):

```bash
# Find your Wireshark plugins directory
wireshark -G plugins

# Copy dissectors there (example path)
sudo cp dissectors/*.lua /usr/lib/wireshark/plugins/
```

## Verifying Installation

1. Open Wireshark
2. Go to **Help** → **About Wireshark** → **Plugins**
3. Look for `http_custom` and `dns_custom` in the list

## Using in stooge

The stooge traffic replayer will automatically load these dissectors when analysing PCAP files, providing detailed protocol breakdowns during replay.

## Developing Custom Dissectors

See Wireshark's [Lua API documentation](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html) for creating your own protocol dissectors.

### Basic Template

```lua
local my_proto = Proto("my_protocol", "My Protocol")

local f_field = ProtoField.string("my_protocol.field", "Field Name")
my_proto.fields = {f_field}

function my_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "MYPROTO"
    local subtree = tree:add(my_proto, buffer())
    subtree:add(f_field, buffer(0, 10))
    return buffer:len()
end

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(12345, my_proto)
```

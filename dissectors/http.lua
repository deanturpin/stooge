-- HTTP dissector for Wireshark/stooge
-- Parses HTTP requests and responses from TCP streams

local http_proto = Proto("http_custom", "HTTP Protocol")

-- Protocol fields
local f_method = ProtoField.string("http.method", "Method")
local f_uri = ProtoField.string("http.uri", "URI")
local f_version = ProtoField.string("http.version", "Version")
local f_status_code = ProtoField.uint16("http.status_code", "Status Code")
local f_status_text = ProtoField.string("http.status_text", "Status Text")
local f_header = ProtoField.string("http.header", "Header")
local f_body = ProtoField.string("http.body", "Body")

http_proto.fields = {f_method, f_uri, f_version, f_status_code, f_status_text, f_header, f_body}

-- Dissector function
function http_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = "HTTP"

    local subtree = tree:add(http_proto, buffer(), "HTTP Protocol")

    -- Convert buffer to string for parsing
    local data = buffer():string()

    -- Check if this is a request or response
    local is_request = data:match("^(%a+)%s+")
    local is_response = data:match("^HTTP/")

    if is_request then
        -- Parse HTTP request: METHOD URI VERSION
        local method, uri, version = data:match("^(%a+)%s+([^%s]+)%s+HTTP/([%d%.]+)")
        if method then
            subtree:add(f_method, method)
            subtree:add(f_uri, uri)
            subtree:add(f_version, version)
            pinfo.cols.info = method .. " " .. uri
        end
    elseif is_response then
        -- Parse HTTP response: VERSION STATUS_CODE STATUS_TEXT
        local version, status_code, status_text = data:match("^HTTP/([%d%.]+)%s+(%d+)%s+([^\r\n]+)")
        if version and status_code then
            subtree:add(f_version, version)
            subtree:add(f_status_code, tonumber(status_code))
            subtree:add(f_status_text, status_text)
            pinfo.cols.info = "HTTP/" .. version .. " " .. status_code .. " " .. status_text
        end
    end

    -- Parse headers (lines between first line and blank line)
    for header in data:gmatch("\r?\n([^:\r\n]+:[^\r\n]+)") do
        subtree:add(f_header, header)
    end

    return length
end

-- Register dissector on common HTTP ports
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(80, http_proto)
tcp_table:add(8080, http_proto)
tcp_table:add(443, http_proto) -- HTTPS (encrypted, won't parse correctly but registered)

-- DNS dissector for Wireshark/stooge
-- Parses DNS queries and responses from UDP/TCP packets

local dns_proto = Proto("dns_custom", "DNS Protocol")

-- Protocol fields
local f_transaction_id = ProtoField.uint16("dns.id", "Transaction ID", base.HEX)
local f_flags = ProtoField.uint16("dns.flags", "Flags", base.HEX)
local f_qr = ProtoField.uint16("dns.qr", "Query/Response", base.DEC, {[0]="Query", [1]="Response"})
local f_opcode = ProtoField.uint16("dns.opcode", "Opcode")
local f_question_count = ProtoField.uint16("dns.qd_count", "Questions")
local f_answer_count = ProtoField.uint16("dns.an_count", "Answers")
local f_authority_count = ProtoField.uint16("dns.ns_count", "Authority RRs")
local f_additional_count = ProtoField.uint16("dns.ar_count", "Additional RRs")
local f_query_name = ProtoField.string("dns.qry.name", "Query Name")
local f_query_type = ProtoField.uint16("dns.qry.type", "Query Type")
local f_query_class = ProtoField.uint16("dns.qry.class", "Query Class")

dns_proto.fields = {
    f_transaction_id, f_flags, f_qr, f_opcode,
    f_question_count, f_answer_count, f_authority_count, f_additional_count,
    f_query_name, f_query_type, f_query_class
}

-- DNS query types (common ones)
local query_types = {
    [1] = "A",
    [2] = "NS",
    [5] = "CNAME",
    [6] = "SOA",
    [12] = "PTR",
    [15] = "MX",
    [16] = "TXT",
    [28] = "AAAA",
    [33] = "SRV",
    [255] = "ANY"
}

-- Parse DNS name from buffer (handles compression)
function parse_dns_name(buffer, offset)
    local name = ""
    local pos = offset

    while pos < buffer:len() do
        local len = buffer(pos, 1):uint()
        if len == 0 then
            pos = pos + 1
            break
        end

        -- Check for compression pointer (top 2 bits set)
        if len >= 192 then
            pos = pos + 2
            name = name .. ".<compressed>"
            break
        end

        if name ~= "" then
            name = name .. "."
        end

        pos = pos + 1
        if pos + len <= buffer:len() then
            name = name .. buffer(pos, len):string()
            pos = pos + len
        else
            break
        end
    end

    return name, pos
end

-- Dissector function
function dns_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 12 then return end -- Minimum DNS header size

    pinfo.cols.protocol = "DNS"

    local subtree = tree:add(dns_proto, buffer(), "DNS Protocol")

    -- Parse DNS header (12 bytes)
    local transaction_id = buffer(0, 2):uint()
    local flags = buffer(2, 2):uint()
    local qr = bit32.band(bit32.rshift(flags, 15), 0x1)
    local opcode = bit32.band(bit32.rshift(flags, 11), 0xF)
    local qd_count = buffer(4, 2):uint()
    local an_count = buffer(6, 2):uint()
    local ns_count = buffer(8, 2):uint()
    local ar_count = buffer(10, 2):uint()

    subtree:add(f_transaction_id, buffer(0, 2))
    subtree:add(f_flags, buffer(2, 2))
    subtree:add(f_qr, qr)
    subtree:add(f_opcode, opcode)
    subtree:add(f_question_count, buffer(4, 2))
    subtree:add(f_answer_count, buffer(6, 2))
    subtree:add(f_authority_count, buffer(8, 2))
    subtree:add(f_additional_count, buffer(10, 2))

    -- Parse question section
    local offset = 12
    if qd_count > 0 and offset < length then
        local qname, new_offset = parse_dns_name(buffer, offset)
        offset = new_offset

        if offset + 4 <= length then
            local qtype = buffer(offset, 2):uint()
            local qclass = buffer(offset + 2, 2):uint()

            subtree:add(f_query_name, qname)
            subtree:add(f_query_type, buffer(offset, 2))
            subtree:add(f_query_class, buffer(offset + 2, 2))

            local qtype_name = query_types[qtype] or tostring(qtype)
            local qr_type = qr == 1 and "Response" or "Query"
            pinfo.cols.info = string.format("DNS %s: %s %s", qr_type, qname, qtype_name)
        end
    end

    return length
end

-- Register dissector on DNS port
local udp_table = DissectorTable.get("udp.port")
udp_table:add(53, dns_proto)

local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(53, dns_proto)

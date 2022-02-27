tcpshark = Proto("TCPShark", "TCPShark data")

local TCPSHARK_MAGIC = 0xA1BFF3D4

local fields = {}

fields.magic   = ProtoField.uint32("tcpshark.magic", "Magic", base.HEX)
fields.pid     = ProtoField.int32("tcpshark.pid", "PID", base.DEC)
fields.Cmd = ProtoField.string("tcpshark.Cmd", "Cmd", base.ASCII)
fields.Args = ProtoField.string("tcpshark.Args", "Args", base.ASCII)

tcpshark.fields = fields

function tcpshark.dissector(buffer, pinfo, tree)

  -- for now only IP packets are supported
  eth_header_protocol = buffer(12 ,2):uint()
  if eth_header_protocol ~= 0x800 then
    return
  end

  -- ethernet header is always 14 bytes, and after 2 bytes into IP header, you'll have IP packet's total length
  local ethernet_header_size = 14
  local iplen = buffer(16 ,2):uint()
  local framelen = buffer:len()
  local trailerlength = framelen - ethernet_header_size - iplen

  -- -4: skip the FCS
  local trailer = buffer(iplen+ethernet_header_size ,trailerlength )
  
  -- simple sanity check with the magic number
  local magic = trailer(0, 4):uint()
  if(magic ~= TCPSHARK_MAGIC) then
    return
  end

  local pid = trailer(4, 4):uint()
  
  local subtree = tree:add(tcpshark, buffer(), string.format("Tcpshark, pid: %d",pid))
  subtree:add(fields.pid, pid)
  local cmdLen =  trailer(8, 1):uint()
  subtree:add(fields.Cmd, trailer(9,cmdLen))
  local argsLen = trailer(9+cmdLen, 2):uint()
  -- subtree:add(fields.ArgsLen, trailer(9+cmdLen,argsLen)) 
  local args = trailer(11+cmdLen, argsLen):string()
  subtree:add(fields.Args, args)
end

register_postdissector(tcpshark)

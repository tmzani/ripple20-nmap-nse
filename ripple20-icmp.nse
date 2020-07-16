local bin = require "bin"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local ipOps = require "ipOps"
local string = require "string"

local openssl = stdnse.silent_require "openssl"

local hIndex = openssl.md5(SCRIPT_NAME)
local try = nmap.new_try()
local pTimeout, ICMP_MS_SYNC_REQ, ICMP_MS_SYNC_RESP = 3, 165, 166

description = [[
Simple Ripple20 Detection Helper. 
Sends ICMP MS_SYNC_REQ and awaits for a ICMP MS_SYNC_RESP reponse. If positive, it will flag a possible Treck TCP/IP stack.

Cheers to Julio Fort (Blaze Security) for helping out.
Cheers also from CONVISO AppSecurity team for testing (conviso.com.br).

Sample packet:
        0x0000:  4500 0022 beef 0000 ff01 833e ac1e 116f  E..".......>...o
        0x0010:  ac1e 1001 a500 6e22 dead beef 7269 7070  ......n"....ripp
        0x0020:  6c65                                     le
]]

-- @usage
-- nmap [--anonymize <1|0>] [--timeout <secs>]
--
-- @args ripple20-icmp.anonymize number should we randomize icmp payload (otherwise we will mark packets with 0xdeadbeef for diagnose purposes - default will not anonymize)
-- @args ripple20-icmp.timeout number time to wait for icmp packets (default 3 secs)
--
-- @output
-- |_ripple20-icmp: Received ICMP MS_SYNC RESP for IP 172.30.16.1 -- possible Treck TCP/IP stack.
--
--

author = "Thiago Zaninotti (nstalker.com)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","safe"}

local print_table = function(t)
	for k,v in pairs(t) do
		stdnse.print_debug ( 1, " print_table() -> %s : %s", k,v)
	end
end

prerule = function()
	nmap.registry[hIndex] = nmap.is_privileged() and true or false
	stdnse.print_debug ( 1, " RIPPLE20 ICMP test ENABLED.")
	return false
end

hostrule = function(host)
	stdnse.print_debug ( 1, " Running RIPPLE20 ICMP test for %s", host.name)
	return true
end

action = function(host)
	-- sanity check (do I have root permission?)
	if ( host == nil or host.interface == nil or nmap.registry[hIndex] ~= true) then
		return false
	end

	local anon = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".anonymize")) or 0
	local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or pTimeout
	timeout = timeout * 1000

	local iInfo, output = nmap.get_interface_info(host.interface), nil
	local icmp = packet.Packet:new()

	icmp.mac_src = iInfo.mac_addr
	icmp.mac_dst = host.mac_addr
	icmp.ip_p = 1 -- IPPROTO_ICMP
	icmp.ip_bin_src = ipOps.ip_to_str(iInfo.address)
	icmp.ip_bin_dst = ipOps.ip_to_str(host.ip)

	icmp.icmp = true
	icmp.icmp_type = ICMP_MS_SYNC_REQ
	icmp.icmp_code = 0

	if ( anon == 0) then	
		icmp.icmp_payload = packet.numtostr16(0xdead) .. packet.numtostr16(0xbeef) .. "ripple"
	else
		icmp.icmp_payload = openssl.rand_bytes(2) .. openssl.rand_bytes(2) .. openssl.rand_bytes(8)
	end

	icmp:build_icmp_header()
	icmp:build_ip_packet()
	
	local dnet = nmap.new_dnet()
	dnet:ip_open()

	local pcap = nmap.new_socket()
	pcap:set_timeout(timeout)
	stdnse.print_debug ( 1, "(timeout %d) -> (%s) filter: %s", timeout, iInfo.device, string.format ( "icmp and src %s", host.ip))
	pcap:pcap_open ( iInfo.device, 104, false, string.format ( "icmp and src %s", host.ip))

	dnet:ip_send ( icmp.buf, host)
	local status, len, _, respdata, _ = pcap:pcap_receive()	

	if ( status) then	
		local response = packet.Packet:new ( respdata, len, false)
		if ( response:ip_parse() and response:icmp_parse() and response.icmp_type == ICMP_MS_SYNC_RESP) then
			stdnse.print_debug ( 1, "Found ----> IP %s | ICMP Type %d", response.ip_src, response.icmp_type)
			output = string.format ( "Received ICMP MS_SYNC RESP for IP %s -- possible Treck TCP/IP stack.", host.ip)
		end
	end

	pcap:pcap_close()
	dnet:ip_close()

	return output
end

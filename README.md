# ripple20-nmap-nse

Simple NSE version of treck's tcp/ip stack fingerprinting (via icmp).This is a simple discovery tool. It will throw a ICMP MS_SYNC_REQ (0xa5) against the potential target and will wait for a MS_SYNC_RESP (0xa6). This seems to be an unique behavior of Treck's TCP/IP stack. You are welcome to improve the code. 

basic usage: nmap --script ripple20-icmp.nse <target> 

author:
Thiago Zaninotti
NStalker

Apparently the IPv6/IPv4 PoC fragment has a low reliability to test the presence of Ripple20 or Treck's TCP/IP library. So the idea is to stick with ICMP 0xa5 probe that seems to be more reliable for an initial assessment. 

Kudos goes to:
- Julio Fort (Blaze Security)
- Conviso AppSec Team (convisoappsec.com)

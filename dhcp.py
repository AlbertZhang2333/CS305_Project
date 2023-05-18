from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from datetime import datetime
class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99' # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8' # don't modify, just for the dns entry
    start_ip = '192.168.1.3' # can be modified
    end_ip = '192.168.1.100' # can be modified
    netmask = '255.255.255.0' # can be modified
    server_ip = '192.168.1.2'
    gateway = '192.168.1.1'
    subnet = '192.168.1.0'
    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.


class DHCPServer():
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns
    server_ip = Config.server_ip
    gateway = Config.gateway
    subnet = Config.subnet
    
    
    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
        req_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        
        eth_pkt = ethernet.ethernet(pkt)
        ip_pkt = eth_pkt.payload
        udp_pkt = ip_pkt.payload
        dhcp_pkt = dhcp.dhcp(udp_pkt.payload)
        for opt in dhcp_pkt.options:
            if opt[0] == 'requested_addr':
                req_ip = opt[1]
                break

        req_ip_parts = list(map(int, req_ip.split('.')))
        req_ip_int = (req_ip_parts[0] << 24) + (req_ip_parts[1] << 16) + (req_ip_parts[2] << 8) + req_ip_parts[3]
    
        start_ip_parts = list(map(int, DHCPServer.start_ip.split('.')))
        start_ip_int = (start_ip_parts[0] << 24) + (start_ip_parts[1] << 16) + (start_ip_parts[2] << 8) + start_ip_parts[3]
    
        end_ip_parts = list(map(int, DHCPServer.end_ip.split('.')))
        end_ip_int = (end_ip_parts[0] << 24) + (end_ip_parts[1] << 16) + (end_ip_parts[2] << 8) + end_ip_parts[3]
        if req_ip_int >= start_ip_int and req_ip_int <= end_ip_int:
            client_mac = req_eth.src
            # Create a DHCP ack packet
            ack_pkt = packet.Packet()
            ack_pkt.add_protocol(ethernet.ethernet(
                ethertype=req_eth.ethertype,
                dst=client_mac,
                src=DHCPServer.hardware_addr, 
            ))
            ack_pkt.add_protocol(ipv4.ipv4(
                version=pkt_ip.version,
                header_length=pkt_ip.header_length,
                ttl=pkt_ip.ttl,
                proto=pkt_ip.proto,
                src=pkt_ip.dst,  # Set the server's IP address
                dst="255.255.255.255",  # Set the broadcast address
            ))
            ack_pkt.add_protocol(udp.udp(
                src_port=pkt_udp.dst_port,
                dst_port=pkt_udp.src_port,
            ))
            ack_pkt.add_protocol(dhcp.dhcp(
                op=dhcp.DHCP_BOOTREPLY,
                hlen=pkt_dhcp.hlen,
                hops=pkt_dhcp.hops,
                xid=pkt_dhcp.xid,
                secs=pkt_dhcp.secs,
                flags=pkt_dhcp.flags,
                ciaddr="0.0.0.0",
                yiaddr=req_ip,
                siaddr="0.0.0.0",
                giaddr=pkt_dhcp.giaddr,
                chaddr=pkt_dhcp.chaddr,
                options=[dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT, value=dhcp.DHCP_ACK),
                    dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT, value=DHCPServer.server_ip),  # Set the server's IP address
                    dhcp.option(tag=dhcp.DHCP_LEASE_TIME_OPT, value=3600),  # Set the lease duration in seconds
                    dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT, value=DHCPServer.subnet),
                    dhcp.option(tag=dhcp.DHCP_DNS_SERVER_OPT, value=DHCPServer.dns),  # Set the DNS server's IP address
                    dhcp.option(tag=dhcp.DHCP_END_OPT)]))
            return ack_pkt
        else:
            return

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        discover = dhcp.dhcp.parser(pkt.data)
        ether = pkt.get_protocol(ethernet.ethernet)

        # create the DHCP Offer packet
        offer = dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,
            chaddr=discover.chaddr,
            xid=discover.xid,
            yiaddr=DHCPServer.start_ip,
            options=[dhcp.option(dhcp.DHCP_MESSAGE_TYPE_OPT, dhcp.DHCP_OFFER),
                    dhcp.option(dhcp.DHCP_SERVER_IDENTIFIER_OPT, DHCPServer.server_ip),
                    dhcp.option(dhcp.DHCP_LEASE_TIME_OPT, datetime.now()),
                    dhcp.option(dhcp.DHCP_SUBNET_MASK_OPT, DHCPServer.netmask),
                    dhcp.option(dhcp.DHCP_ROUTER_OPT, DHCPServer.gateway),
                    dhcp.option(dhcp.DHCP_DNS_SERVER_OPT, DHCPServer.dns)]
        )

        # set the source and destination addresses of the offer packet
        offer_pkt = ethernet.ethernet(
            dst=pkt.src,
            src=DHCPServer.hardware_addr,
            ethertype=ether.ETH_TYPE_IP,
            data=ipv4.ipv4(
                src=DHCPServer.server_ip,
                dst='255.255.255.255',
                proto=ipv4.inet.IPPROTO_UDP,
                ttl=64,
                flags=0,
                options=[],
                data=udp.udp(
                    src_port=dhcp.DHCP_SERVER_PORT,
                    dst_port=dhcp.DHCP_CLIENT_PORT,
                    data=dhcp.dhcp.serialize(offer)
                )
            )
        )

        return offer_pkt
            


    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        # TODO: Specify the type of received DHCP packet
        # You may choose a valid IP from IP pool and genereate DHCP OFFER packet
        # Or generate a DHCP ACK packet
        # Finally send the generated packet to the host by using _send_packet method
        pkt_dhcp = pkt.get_protocols(dhcp.dhcp)[0]
        dhcp_state = ord(
            [opt for opt in pkt_dhcp.options.option_list if opt.tag == 53][0].value)
        if dhcp_state == 1:
            cls._send_packet(datapath, port, cls.assemble_offer(pkt, datapath))
        elif dhcp_state == 3:
            cls._send_packet(datapath, port, cls.assemble_ack(pkt, datapath, port))
        else:
            return

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if isinstance(pkt, str):
            pkt = pkt.encode()
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

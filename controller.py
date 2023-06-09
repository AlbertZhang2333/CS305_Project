from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology import event, switches
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import udp
from dhcp import DHCPServer

class ControllerApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    mac_table = {}
    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        """
        Event handler indicating a switch has come online.
        """

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        """
        Event handler indicating a switch has been removed
        """


    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        """
        Event handler indiciating a host has joined the network
        This handler is automatically triggered when a host sends an ARP response.
        """ 
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        """
        Event handler indicating a link between two switches has been added
        """
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        Event handler indicating when a link between two switches has been deleted
        """
        # TODO:  Update network topology and flow rules
   
        

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        # TODO:  Update network topology and flow rules

    mac_table = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            pkt = packet.Packet(data=msg.data)
            pkt_dhcp = pkt.get_protocols(dhcp.dhcp)
            inPort = msg.in_port
            if not pkt_dhcp:
                arp_pkt = pkt.get_protocols(arp.arp)
                if arp_pkt:
                    self.handle_arp_packet(arp_pkt, datapath, inPort)

            else:
                DHCPServer.handle_dhcp(datapath, inPort, pkt)      
            return 
        except Exception as e:
            self.logger.error(e)
    
    
    def handle_arp_packet(self, arp_pkt, datapath, in_port):
        src_mac = arp_pkt.src_mac
        src_ip = arp_pkt.src_ip
        dst_mac = arp_pkt.dst_mac
        dst_ip = arp_pkt.dst_ip
        if arp_pkt.opcode == arp.ARP_REQUEST:
            # Process the ARP request
            pass
        elif arp_pkt.opcode == arp.ARP_REPLY:
            # Process the ARP reply
            pass

        # Construct and send the ARP reply packet

        eth_pkt = ethernet.ethernet(dst_mac, src_mac, ethernet.ETH_TYPE_ARP)
        arp_reply = arp.arp(hwtype=1, proto=ethernet.ETH_TYPE_IP, hlen=6, plen=4, opcode=arp.ARP_REPLY,
                            src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip)
        pkt_out = packet.Packet()
        pkt_out.add_protocol(eth_pkt)
        pkt_out.add_protocol(arp_reply)
        pkt_out.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto_v1_0.OFPP_FLOOD, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, in_port=in_port,
            actions=actions, data=pkt_out.data)
        datapath.send_msg(out)

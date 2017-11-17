# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.misc.config import *

log = core.getLogger()



class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_firewall (self, packet, packet_in):
    tcp_pkt = packet.find('tcp')
    udp_pkt = packet.find('udp')
    ip_pkt = packet.find('ipv4')
    drop_pkt = False

    if ip_pkt:
      if BLOCKED_IP_SRC is None or BLOCKED_IP_DST is None:
        drop_pkt = True
        log.info('DETECTED IP PACKET WHEN ALL IPs ARE BLOCKED,'
                 ' dropping packet.')
      elif ip_pkt.srcip in BLOCKED_IP_SRC:
        drop_pkt = True
        log.info('DETECTED BLACKLISTED SOURCE IP %s, dropping packet'
                 % ip_pkt.srcip)
      elif ip_pkt.dstip in BLOCKED_IP_DST:
        drop_pkt = True
        log.info('DETECTED BLACKLISTED DESTINATION IP %s, dropping packet'
                 % ip_pkt.dstip)

    if not drop_pkt and tcp_pkt and BLOCK_TCP:
      if TCP_BLOCKED_PORTS is None:
        drop_pkt = True
        log.info('DETECTED TCP PACKET WHEN TCP IS BLOCKED, dropping packet.')
      elif int(tcp_pkt.dstport) in TCP_BLOCKED_PORTS:
        drop_pkt = True
        log.info('DETECTED BLACKLISTED TCP PORT %s, dropping packet'
                   % tcp_pkt.dstport)

    if not drop_pkt and udp_pkt and BLOCK_UDP:
      if UDP_BLOCKED_PORTS is None:
        drop_pkt = True
        log.info('DETECTED UDP PACKET WHEN UDP IS BLOCKED, dropping packet')
      elif int(udp_pkt.dstport) in UDP_BLOCKED_PORTS:
        drop_pkt = True
        log.info('DETECTED BLACKLISTED UDP PORT %s, dropping packet'
                 % udp_pkt.dstport)

    if not drop_pkt:
      self.resend_packet(packet_in, of.OFPP_ALL)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    self.act_like_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)

// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_multipath_configuration.h"

namespace net {

QuicMultipathConfiguration::QuicMultipathConfiguration()
    : QuicMultipathConfiguration(DEFAULT_PACKET_SCHEDULING,
        DEFAULT_ACK_HANDLING, true) {
}

QuicMultipathConfiguration::QuicMultipathConfiguration(
    const QuicMultipathConfiguration& other)
    : packet_scheduling_(other.packet_scheduling_), ack_sending_(
        other.ack_sending_), client_ports_(other.client_ports_), client_ip_address_(
        other.client_ip_address_) {

}

QuicMultipathConfiguration::QuicMultipathConfiguration(
    PacketScheduling packetScheduling, AckSending ackSending, bool usingPacing)
    : QuicMultipathConfiguration(packetScheduling, ackSending,
        std::vector<unsigned int>(), QuicIpAddress(), usingPacing) {

}

QuicMultipathConfiguration::QuicMultipathConfiguration(
    PacketScheduling packetScheduling, AckSending ackSending,
    std::vector<unsigned int> clientPorts, QuicIpAddress clientIpAddress,
    bool usingPacing)
    : packet_scheduling_(packetScheduling), ack_sending_(ackSending), client_ports_(
        clientPorts), client_ip_address_(clientIpAddress), using_pacing_(
        usingPacing) {

}

QuicMultipathConfiguration::~QuicMultipathConfiguration() {

}

QuicMultipathConfiguration QuicMultipathConfiguration::CreateClientConfiguration(
    PacketScheduling packetScheduling, AckSending ackSending,
    std::vector<unsigned int> clientPorts, bool usingPacing) {
  return QuicMultipathConfiguration::CreateClientConfiguration(packetScheduling,
      ackSending, clientPorts, QuicIpAddress(), usingPacing);
}

QuicMultipathConfiguration QuicMultipathConfiguration::CreateClientConfiguration(
    PacketScheduling packetScheduling, AckSending ackSending,
    std::vector<unsigned int> clientPorts, QuicIpAddress clientIpAddress,
    bool usingPacing) {
  return QuicMultipathConfiguration(packetScheduling, ackSending, clientPorts,
      clientIpAddress, usingPacing);
}

QuicMultipathConfiguration QuicMultipathConfiguration::CreateServerConfiguration(
    PacketScheduling packetScheduling, AckSending ackSending,
    bool usingPacing) {
  return QuicMultipathConfiguration(packetScheduling, ackSending, usingPacing);
}

} // namespace net

// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_multipath_configuration.h"

namespace net {

QuicMultipathConfiguration::QuicMultipathConfiguration()
    : QuicMultipathConfiguration(DEFAULT_PACKET_SCHEDULING,
        DEFAULT_ACK_HANDLING) {
}

QuicMultipathConfiguration::QuicMultipathConfiguration(
    PacketScheduling packetScheduling, AckSending ackSending)
    : QuicMultipathConfiguration(packetScheduling, ackSending, std::vector<unsigned int>()) {

}

QuicMultipathConfiguration::QuicMultipathConfiguration(
    PacketScheduling packetScheduling, AckSending ackSending,
    std::vector<unsigned int> clientPorts)
    : packet_scheduling_(packetScheduling), ack_sending_(ackSending), client_ports_(
        clientPorts) {

}

QuicMultipathConfiguration::~QuicMultipathConfiguration() {

}

} // namespace net

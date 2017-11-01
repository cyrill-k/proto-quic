// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_MULTIPATH_CONFIGURATION_H_
#define NET_QUIC_CORE_QUIC_MULTIPATH_CONFIGURATION_H_

#include "base/macros.h"
#include "net/quic/platform/api/quic_export.h"

#include <vector>

namespace net {

class QUIC_EXPORT_PRIVATE QuicMultipathConfiguration {
public:
  enum class PacketScheduling {
    ROUNDROBIN, SMALLEST_RTT_FIRST
  };

  enum class AckSending {
    SIMPLE, ROUNDROBIN, SEND_ON_SMALLEST_RTT
  };

  static const AckSending DEFAULT_ACK_HANDLING = AckSending::SEND_ON_SMALLEST_RTT;
  static const PacketScheduling DEFAULT_PACKET_SCHEDULING = PacketScheduling::SMALLEST_RTT_FIRST;

  QuicMultipathConfiguration();
  QuicMultipathConfiguration(PacketScheduling packetScheduling,
      AckSending ackSending);
  QuicMultipathConfiguration(PacketScheduling packetScheduling,
      AckSending ackSending, std::vector<unsigned int> clientPorts);
  ~QuicMultipathConfiguration();

  PacketScheduling GetPacketSchedulingConfiguration() const {
    return packet_scheduling_;
  }
  AckSending GetAckSendingConfiguration() const {
    return ack_sending_;
  }
  const std::vector<unsigned int>& GetClientPorts() const {
    return client_ports_;
  }

private:
  PacketScheduling packet_scheduling_;
  AckSending ack_sending_;
  std::vector<unsigned int> client_ports_;
};

}

#endif  // NET_QUIC_CORE_QUIC_MULTIPATH_CONFIGURATION_H_

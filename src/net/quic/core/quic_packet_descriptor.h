// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_PLATFORM_API_QUIC_PACKET_DESCRIPTOR_H_
#define NET_QUIC_PLATFORM_API_QUIC_PACKET_DESCRIPTOR_H_

#include <iostream>
#include <iomanip>
#include <functional>
#include <string>
#include <unordered_set>

#include "net/quic/platform/api/quic_export.h"
#include "net/quic/platform/api/quic_subflow_descriptor.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/core/quic_utils.h"

namespace net {


class QUIC_EXPORT_PRIVATE QuicPacketDescriptor {
public:
  QuicPacketDescriptor();
  QuicPacketDescriptor(const QuicPacketDescriptor& other) = default;
  QuicPacketDescriptor(QuicPacketNumber packetNumber);
  QuicPacketDescriptor(QuicSubflowDescriptor subflowDescriptor, QuicPacketNumber packetNumber);
  QuicPacketDescriptor& operator=(const QuicPacketDescriptor& other) = default;
  QuicPacketDescriptor& operator=(QuicPacketDescriptor&& other) = default;
  QUIC_EXPORT_PRIVATE friend bool operator==(const QuicPacketDescriptor& lhs,
      const QuicPacketDescriptor& rhs);
  QUIC_EXPORT_PRIVATE friend bool operator!=(const QuicPacketDescriptor& lhs,
      const QuicPacketDescriptor& rhs);
  QUIC_EXPORT_PRIVATE friend bool operator<(const QuicPacketDescriptor& lhs,
      const QuicPacketDescriptor& rhs);

  bool IsInitialized() const;
  std::string ToString() const;

  QuicSubflowDescriptor SubflowDescriptor() const {return subflow_descriptor_;}
  QuicPacketNumber PacketNumber() const {return packet_number_;}

private:
  QuicSubflowDescriptor subflow_descriptor_;
  QuicPacketNumber packet_number_;
  bool initialized_;
};

} /* namespace net */


namespace std {

template<> struct hash<net::QuicPacketDescriptor> {
  typedef net::QuicPacketDescriptor argument_type;
  typedef std::size_t result_type;
  result_type operator()(argument_type const& s) const {
    result_type result = std::hash<net::QuicPacketNumber> { }(s.PacketNumber());
    net::QuicUtils::hash_combine(result, s.SubflowDescriptor().Self().host().ToString());
    net::QuicUtils::hash_combine(result, s.SubflowDescriptor().Self().port());
    net::QuicUtils::hash_combine(result, s.SubflowDescriptor().Peer().host().ToString());
    net::QuicUtils::hash_combine(result, s.SubflowDescriptor().Peer().port());
    return result;
  }
};

}
#endif /* NET_QUIC_PLATFORM_API_QUIC_PACKET_DESCRIPTOR_H_ */

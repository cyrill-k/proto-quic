/*
 * quic_packet_descriptor.cpp
 *
 *  Created on: Sep 2, 2017
 *      Author: cyrill
 */

#include "net/quic/core/quic_packet_descriptor.h"

namespace net {

QuicPacketDescriptor::QuicPacketDescriptor() :
    subflow_descriptor_(QuicSubflowDescriptor()), packet_number_(0),
    initialized_(false) {
}

QuicPacketDescriptor::QuicPacketDescriptor(
    QuicSubflowDescriptor subflowDescriptor, QuicPacketNumber packetNumber) :
    subflow_descriptor_(subflowDescriptor), packet_number_(packetNumber),
    initialized_(true) {
}

bool operator==(const QuicPacketDescriptor& lhs,
    const QuicPacketDescriptor& rhs) {
  return lhs.subflow_descriptor_ == rhs.subflow_descriptor_ &&
      lhs.packet_number_ == rhs.packet_number_ &&
      lhs.initialized_ == rhs.initialized_;
}

bool operator!=(const QuicPacketDescriptor& lhs,
    const QuicPacketDescriptor& rhs) {
  return !(lhs == rhs);
}

bool operator<(const QuicPacketDescriptor& lhs,
    const QuicPacketDescriptor& rhs) {
  if(!lhs.IsInitialized() && rhs.IsInitialized())
    return true;
  if(lhs.IsInitialized() && !rhs.IsInitialized())
    return false;

  if(lhs.SubflowDescriptor() < rhs.SubflowDescriptor())
    return true;
  if(rhs.SubflowDescriptor() < lhs.SubflowDescriptor())
    return false;
  if(lhs.PacketNumber() < rhs.PacketNumber())
    return true;
  return false;
}

bool QuicPacketDescriptor::IsInitialized() const {
  return initialized_;
}

std::string QuicPacketDescriptor::ToString() const {
  return subflow_descriptor_.ToString() + "," + std::to_string(packet_number_);
}

} /* namespace net */

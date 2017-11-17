// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A send algorithm that adds pacing on top of an another send algorithm.
// It uses the underlying sender's pacing rate to schedule packets.
// It also takes into consideration the expected granularity of the underlying
// alarm to ensure that alarms are not set too aggressively, and err towards
// sending packets too early instead of too late.

#ifndef NET_QUIC_CORE_CONGESTION_CONTROL_MULTIPATH_PACING_SENDER_H_
#define NET_QUIC_CORE_CONGESTION_CONTROL_MULTIPATH_PACING_SENDER_H_

#include <cstdint>
#include <map>
#include <memory>

#include "base/macros.h"
#include "net/quic/core/quic_bandwidth.h"
#include "net/quic/core/quic_config.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_time.h"
#include "net/quic/platform/api/quic_export.h"
#include "net/quic/core/congestion_control/multipath_send_algorithm_interface.h"

namespace net {

class QUIC_EXPORT_PRIVATE MultipathPacingSender {
public:
  MultipathPacingSender();
  ~MultipathPacingSender();

  // 7 * MSS ~= 10k
  // setting kMaxConsecutiveMakingUpTime = 0 means there is no limit of
  // consecutive making up time.
  const uint32_t kMaxConsecutiveMakingUpTime = 7;

  // Sets the underlying sender. Does not take ownership of |sender|. |sender|
  // must not be null. This must be called before any of the
  // SendAlgorithmInterface wrapper methods are called.
  void set_sender(MultipathSendAlgorithmInterface* sender);

  void set_max_pacing_rate(QuicBandwidth max_pacing_rate) {
    max_pacing_rate_ = max_pacing_rate;
  }

  void OnCongestionEvent(const QuicSubflowDescriptor& descriptor,
      bool rtt_updated, QuicByteCount bytes_in_flight, QuicTime event_time,
      const MultipathSendAlgorithmInterface::CongestionVector& acked_packets,
      const MultipathSendAlgorithmInterface::CongestionVector& lost_packets);

  bool OnPacketSent(const QuicSubflowDescriptor& descriptor, QuicTime sent_time,
      QuicByteCount bytes_in_flight, QuicPacketNumber packet_number,
      QuicByteCount bytes, HasRetransmittableData is_retransmittable);

  QuicTime::Delta TimeUntilSend(const QuicSubflowDescriptor& descriptor,
      QuicTime now, QuicByteCount bytes_in_flight);

  QuicBandwidth PacingRate(const QuicSubflowDescriptor& descriptor,
      QuicByteCount bytes_in_flight) const;

private:
  // Underlying sender. Not owned.
  MultipathSendAlgorithmInterface* sender_;
  // If not QuicBandidth::Zero, the maximum rate the PacingSender will use.
  QuicBandwidth max_pacing_rate_;

  // Number of unpaced packets to be sent before packets are delayed.
  uint32_t burst_tokens_;
  // Send time of the last packet considered delayed.
  QuicTime last_delayed_packet_sent_time_;
  QuicTime ideal_next_packet_send_time_; // When can the next packet be sent.
  bool was_last_send_delayed_; // True when the last send was delayed.
  uint32_t consecutive_making_up_time_;

  DISALLOW_COPY_AND_ASSIGN(MultipathPacingSender);
};

} // namespace net

#endif  // NET_QUIC_CORE_CONGESTION_CONTROL_MULTIPATH_PACING_SENDER_H_
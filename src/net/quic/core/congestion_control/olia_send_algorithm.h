// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The pure virtual class for send side congestion control algorithm in a
// multipathing environment.
//
// This interface only operates on subflows where the subflow id is known
// to both endpoints. This means that each subflow has an assigned
// QuicSubflowId and ack frames of this subflow can be interpreted.

#ifndef NET_QUIC_CORE_CONGESTION_CONTROL_OLIA_SEND_ALGORITHM_H_
#define NET_QUIC_CORE_CONGESTION_CONTROL_OLIA_SEND_ALGORITHM_H_

#include <list>

#include "net/quic/platform/api/quic_export.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/core/frames/quic_frame.h"
#include "net/quic/core/congestion_control/multipath_send_algorithm_interface.h"
#include "net/quic/core/congestion_control/multipath_scheduler_algorithm.h"

namespace net {

class QuicSubflowDescriptor;
struct QuicTransmissionInfo;

class QUIC_EXPORT_PRIVATE OliaSendAlgorithm: public MultipathSendAlgorithmInterface {
public:
  OliaSendAlgorithm(MultipathSchedulerInterface* scheduler);
  ~OliaSendAlgorithm()
override  ;

  static bool pathUpdateFrequency;

  const double kMultiplicativeDecreaseFactor = 0.7; //Like kRenoBeta

  void AddSubflow(const QuicSubflowDescriptor& subflowDescriptor,
      RttStats* rttStats, QuicUnackedPacketMap* unackedPacketMap) override;

  void OnLoss(const QuicSubflowDescriptor& descriptor, QuicPacketLength bytes_lost) override;
  void OnAck(const QuicSubflowDescriptor& descriptor, QuicPacketLength bytes_acked) override;
  QuicByteCount CongestionWindowAfterPacketLoss(const QuicSubflowDescriptor& descriptor) override;
  QuicByteCount CongestionWindowAfterPacketAck(
      const QuicSubflowDescriptor& descriptor, QuicByteCount prior_in_flight, QuicPacketLength length) override;

private:
  void DeterminePaths();
  QuicByteCount l(const QuicSubflowDescriptor& descriptor);
  double rtt(const QuicSubflowDescriptor& descriptor) const;
  bool IsInMaxWPaths(const QuicSubflowDescriptor& descriptor);
  bool IsInCollectedPaths(const QuicSubflowDescriptor& descriptor);
  unsigned int NumberOfPaths();
  //void ExitSlowstart(const QuicSubflowDescriptor& descriptor);

  struct OliaSubflowParameters {
    OliaSubflowParameters() : l1r(0), l2r(0), id(current_id_++) {
    }
    QuicByteCount l1r, l2r;
    int id;
  };
  static int current_id_;

  std::map<QuicSubflowDescriptor, OliaSubflowParameters> olia_parameters_;
  std::set<QuicSubflowDescriptor> collected_paths_;
  std::set<QuicSubflowDescriptor> max_w_paths_;

  bool TracksOliaDescriptor(const QuicSubflowDescriptor& descriptor) const {
    return olia_parameters_.find(descriptor) != olia_parameters_.end();
  }
  OliaSubflowParameters& GetOliaParameters(const QuicSubflowDescriptor& descriptor) {
    DCHECK(TracksOliaDescriptor(descriptor));
    return olia_parameters_.at(descriptor);
  }

  int packet_counter_;
  int path_update_frequency_;

  DISALLOW_COPY_AND_ASSIGN(OliaSendAlgorithm);
};

} // namespace net

#endif  // NET_QUIC_CORE_CONGESTION_CONTROL_OLIA_SEND_ALGORITHM_H_

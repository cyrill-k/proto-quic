// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/olia_send_algorithm.h"

#include <math.h>

#include "net/quic/core/quic_constants.h"

namespace net {

int OliaSendAlgorithm::current_id_ = 0;

bool OliaSendAlgorithm::pathUpdateFrequency = 10;

OliaSendAlgorithm::OliaSendAlgorithm(MultipathSchedulerInterface* scheduler)
    : MultipathSendAlgorithmInterface(scheduler), packet_counter_(0), path_update_frequency_(pathUpdateFrequency) {

}
OliaSendAlgorithm::~OliaSendAlgorithm() {

}

void OliaSendAlgorithm::OnLoss(const QuicSubflowDescriptor& descriptor,
    QuicPacketLength bytes_lost) {
  GetOliaParameters(descriptor).l1r = GetOliaParameters(descriptor).l2r;
  GetOliaParameters(descriptor).l2r = 0;
}
void OliaSendAlgorithm::OnAck(const QuicSubflowDescriptor& descriptor,
    QuicPacketLength bytes_acked) {
  GetOliaParameters(descriptor).l2r += bytes_acked;
}
QuicByteCount OliaSendAlgorithm::CongestionWindowAfterPacketLoss(
    const QuicSubflowDescriptor& descriptor) {
  return std::max((QuicByteCount)(cwnd(descriptor) * kMultiplicativeDecreaseFactor),
      GetMinimumCongestionWindow());
}
QuicByteCount OliaSendAlgorithm::CongestionWindowAfterPacketAck(
    const QuicSubflowDescriptor& descriptor, QuicByteCount prior_in_flight,
    QuicPacketLength length) {
  QuicByteCount cwndIncrease;
  if (!IsCwndLimited(descriptor, prior_in_flight)) {
    Log(descriptor, "!cwnd limited -> keep cwnd");
    cwndIncrease = 0;
  } else {
    if (InSlowStart(descriptor)) {
      Log(descriptor, "increase by MSS(" + std::to_string(kDefaultTCPMSS) +")");
      cwndIncrease = kDefaultTCPMSS;
    } else {
      if(++packet_counter_ % path_update_frequency_ == 0)
        DeterminePaths();

      double alpha = 0;
      if (IsInCollectedPaths(descriptor)) {
        alpha = 1.0 / (NumberOfPaths() * collected_paths_.size());
      } else if (IsInMaxWPaths(descriptor) && !collected_paths_.empty()) {
        alpha = -1.0 / (NumberOfPaths() * max_w_paths_.size());
      }

      double sum = 0;
      for (std::pair<QuicSubflowDescriptor, OliaSubflowParameters> p : olia_parameters_) {
        sum += ((double) cwnd(p.first)) / rtt(p.first);
      }

      double MSS_r = kDefaultTCPMSS;

      double left_term = cwnd(descriptor) / (rtt(descriptor) * rtt(descriptor))
          / (sum * sum);

      double right_term = alpha / cwnd(descriptor);

      double w_increase = (left_term + right_term) * MSS_r * length; //GetOliaParameters(descriptor).l2r;

      /*QUIC_LOG(WARNING)
          << "ACK(" << GetOliaParameters(descriptor).id << "," << length << ","
              << rtt(descriptor) << ") w_r_new[" << (cwnd(descriptor) + w_increase)
              << "] = w_r[" << cwnd(descriptor) << "]+(" << left_term << "+alpha["
              << alpha << "]/w_r[" << cwnd(descriptor) << "]["
              << (alpha / cwnd(descriptor)) << "])*MSS_r[" << MSS_r
              << "]*bytes_acked[" << GetOliaParameters(descriptor).l2r << "] ["
              << w_increase << "]";*/

      Log(descriptor, "increase by " + std::to_string(w_increase) + " rtt = " + std::to_string(rtt(descriptor)));
      cwndIncrease = w_increase;

      //  For each ACK on the path r:
      //
      //   - If r is in collected_paths, increase w_r by
      //
      //        w_r/rtt_r^2                          1
      //    -------------------    +     -----------------------       (2)
      //   (SUM (w_p/rtt_p))^2    w_r * number_of_paths * |collected_paths|
      //
      //   multiplied by MSS_r * bytes_acked.
      //
      //
      //   - If r is in max_w_paths and if collected_paths is not empty,
      //   increase w_r by
      //
      //         w_r/rtt_r^2                         1
      //    --------------------    -     ------------------------     (3)
      //    (SUM (w_r/rtt_r))^2     w_r * number_of_paths * |max_w_paths|
      //
      //   multiplied by MSS_r * bytes_acked.
      //
      //   - Otherwise, increase w_r by
      //
      //                          (w_r/rtt_r^2)
      //                  ----------------------------------           (4)
      //                         (SUM (w_r/rtt_r))^2
      //
      //   multiplied by MSS_r * bytes_acked.
    }
  }
  return cwnd(descriptor) + cwndIncrease;
}

void OliaSendAlgorithm::AddSubflow(
    const QuicSubflowDescriptor& subflowDescriptor, RttStats* rttStats,
    QuicUnackedPacketMap* unackedPacketMap) {
  MultipathSendAlgorithmInterface::AddSubflow(subflowDescriptor, rttStats,
      unackedPacketMap);
  olia_parameters_.insert(
      std::pair<const QuicSubflowDescriptor, OliaSubflowParameters>(
          subflowDescriptor, OliaSubflowParameters()));
  DeterminePaths();
}


void OliaSendAlgorithm::DeterminePaths() {
  max_w_paths_.clear();
  QuicByteCount w_max = std::numeric_limits<QuicByteCount>::min();
  for (std::pair<QuicSubflowDescriptor, OliaSubflowParameters> p : olia_parameters_) {
    if (cwnd(p.first) > w_max) {
      w_max = cwnd(p.first);
      max_w_paths_.clear();
      max_w_paths_.insert(p.first);
    } else if (cwnd(p.first) == w_max) {
      max_w_paths_.insert(p.first);
    }
  }

  std::set<QuicSubflowDescriptor> bestPaths;
  double ratio_max = std::numeric_limits<double>::min();
  for (std::pair<QuicSubflowDescriptor, OliaSubflowParameters> p : olia_parameters_) {
    double ratio = ((double) l(p.first)) * l(p.first) / rtt(p.first);
    if (ratio > ratio_max) {
      ratio_max = ratio;
      bestPaths.clear();
      bestPaths.insert(p.first);
    } else if (ratio == ratio_max) {
      bestPaths.insert(p.first);
    }
  }

  collected_paths_.clear();
  for (QuicSubflowDescriptor d : bestPaths) {
    if (!IsInMaxWPaths(d)) {
      collected_paths_.insert(d);
    }
  }
}
QuicByteCount OliaSendAlgorithm::l(const QuicSubflowDescriptor& descriptor) {
  OliaSubflowParameters p = GetOliaParameters(descriptor);
  return std::max(p.l1r, p.l2r);
}
double OliaSendAlgorithm::rtt(
    const QuicSubflowDescriptor& descriptor) const {
  QuicTime::Delta rttDelta = srtt(descriptor);
  if (rttDelta == QuicTime::Delta::Zero()) {
    rttDelta = InitialRtt(descriptor);
  }
  return ((double) rttDelta.ToMicroseconds()) / 1000000;
}
bool OliaSendAlgorithm::IsInMaxWPaths(const QuicSubflowDescriptor& descriptor) {
  return max_w_paths_.find(descriptor) != max_w_paths_.end();
}
bool OliaSendAlgorithm::IsInCollectedPaths(
    const QuicSubflowDescriptor& descriptor) {
  return collected_paths_.find(descriptor) != collected_paths_.end();
}
unsigned int OliaSendAlgorithm::NumberOfPaths() {
  return GetNumberOfSubflows();
}

} // namespace net

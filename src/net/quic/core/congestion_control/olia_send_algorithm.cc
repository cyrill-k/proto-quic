// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/olia_send_algorithm.h"

#include <math.h>

#include "net/quic/core/quic_constants.h"

namespace net {

int OliaSendAlgorithm::current_id_ = 0;

OliaSendAlgorithm::OliaSendAlgorithm(MultipathSchedulerInterface* scheduler)
    : MultipathSendAlgorithmInterface(scheduler) {

}
OliaSendAlgorithm::~OliaSendAlgorithm() {

}
void OliaSendAlgorithm::OnCongestionEvent(
    const QuicSubflowDescriptor& descriptor, bool rtt_updated,
    QuicByteCount prior_in_flight, QuicTime event_time,
    const CongestionVector& acked_packets,
    const CongestionVector& lost_packets) {
  if (rtt_updated) {
    logging_interface_->OnRttUpdated(descriptor,
        GetParameters(descriptor).rtt_stats->smoothed_rtt());
  }
  for (std::pair<QuicPacketNumber, QuicPacketLength> p : acked_packets) {
    Ack(descriptor, p.second, prior_in_flight);
  }
  for (std::pair<QuicPacketNumber, QuicPacketLength> p : lost_packets) {
    Loss(descriptor, p.second, prior_in_flight);
  }
}

bool OliaSendAlgorithm::OnPacketSent(const QuicSubflowDescriptor& descriptor,
    QuicTime sent_time, QuicByteCount bytes_in_flight,
    QuicPacketNumber packet_number, QuicByteCount bytes,
    HasRetransmittableData is_retransmittable) {
  return true;
}

void OliaSendAlgorithm::OnRetransmissionTimeout(
    const QuicSubflowDescriptor& descriptor, bool packets_retransmitted) {
  GetMutableParameters(descriptor).ssthresh = std::max(
      GetParameters(descriptor).congestion_window / 2,
      GetMinimumSlowStartThreshold(descriptor));
  //TODO(cyrill): is min ssthresh = min congestion window?
  GetMutableParameters(descriptor).congestion_window =
      GetMinimumSlowStartThreshold(descriptor);
}

void OliaSendAlgorithm::AddSubflow(
    const QuicSubflowDescriptor& subflowDescriptor, RttStats* rttStats,
    QuicUnackedPacketMap* unackedPacketMap) {
  MultipathSendAlgorithmInterface::AddSubflow(subflowDescriptor, rttStats,
      unackedPacketMap);
  olia_parameters_.insert(
      std::pair<const QuicSubflowDescriptor, OliaSubflowParameters>(
          subflowDescriptor, OliaSubflowParameters()));
}

void OliaSendAlgorithm::SetPacketHandlingMethod(
    QuicMultipathConfiguration::PacketScheduling packetSchedulingMethod) {
  static_cast<MultipathSchedulerAlgorithm*>(GetScheduler())->SetPacketSchedulingMethod(
      packetSchedulingMethod);
}

void OliaSendAlgorithm::Ack(const QuicSubflowDescriptor& descriptor,
    QuicPacketLength length, QuicByteCount prior_in_flight) {
  if (InSlowStart(descriptor)) {
    AckSlowStart(descriptor, prior_in_flight);
  } else {
    AckCongestionAvoidance(descriptor, length, prior_in_flight);
  }

  if (logging_interface_) {
    logging_interface_->OnAck(descriptor, length, w(descriptor),
        InSlowStart(descriptor));
  }
}
void OliaSendAlgorithm::Loss(const QuicSubflowDescriptor& descriptor,
    QuicPacketLength length, QuicByteCount priorInFlight) {
  LossCongestionAvoidance(descriptor, length);

  GetMutableParameters(descriptor).congestion_window =
      CongestionWindowAfterPacketLoss(descriptor,
          GetParameters(descriptor).congestion_window);
  GetMutableParameters(descriptor).ssthresh =
      GetParameters(descriptor).congestion_window;

  if (logging_interface_) {
    logging_interface_->OnLoss(descriptor, length, w(descriptor));
  }
}
void OliaSendAlgorithm::AckSlowStart(const QuicSubflowDescriptor& descriptor,
    QuicByteCount prior_in_flight) {
  if (IsCwndLimited(descriptor, prior_in_flight)) {
    QUIC_LOG(INFO)
        << "ACK(" << GetOliaParameters(descriptor).id << "," << rtt(descriptor)
            << ") cwnd blocked(" << w(descriptor) << " -> "
            << w(descriptor) + GetMaximumSegmentSize(descriptor) << ")";
    w(descriptor) += GetMaximumSegmentSize(descriptor);
  } else {
    QUIC_LOG(INFO)
        << "ACK(" << GetOliaParameters(descriptor).id << "," << rtt(descriptor)
            << ") Not cwnd blocked (" << w(descriptor) << ").";
  }
}

void OliaSendAlgorithm::AckCongestionAvoidance(
    const QuicSubflowDescriptor& descriptor, QuicPacketLength length,
    QuicByteCount prior_in_flight) {
  GetOliaParameters(descriptor).l2r += length;

  if (!IsCwndLimited(descriptor, prior_in_flight)) {
    QUIC_LOG(WARNING)
        << "ACK(" << GetOliaParameters(descriptor).id << "," << length << ","
            << rtt(descriptor) << ") Not cwnd blocked.";
  } else {
    DeterminePaths();

    double alpha = 0;
    if (IsInCollectedPaths(descriptor)) {
      alpha = 1.0 / (NumberOfPaths() * collected_paths_.size());
    } else if (IsInMaxWPaths(descriptor) && !collected_paths_.empty()) {
      alpha = -1.0 / (NumberOfPaths() * max_w_paths_.size());
    }

    double sum = 0;
    for (std::pair<QuicSubflowDescriptor, OliaSubflowParameters> p : olia_parameters_) {
      sum += ((double) w(p.first)) / rtt(p.first);
    }

    double MSS_r = GetMaximumSegmentSize(descriptor);

    double left_term = w(descriptor) / (rtt(descriptor) * rtt(descriptor))
        / (sum * sum);

    double right_term = alpha / w(descriptor);

    double w_increase = (left_term + right_term) * MSS_r
        * length;//GetOliaParameters(descriptor).l2r;

    QUIC_LOG(WARNING)
        << "ACK(" << GetOliaParameters(descriptor).id << "," << length << ","
            << rtt(descriptor) << ") w_r_new[" << (w(descriptor) + w_increase)
            << "] = w_r[" << w(descriptor) << "]+(" << left_term << "+alpha["
            << alpha << "]/w_r[" << w(descriptor) << "]["<<(alpha/w(descriptor)) << "])*MSS_r[" << MSS_r << "]*bytes_acked["
            << GetOliaParameters(descriptor).l2r << "] [" << w_increase << "]";

    w(descriptor) += w_increase;

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

void OliaSendAlgorithm::LossCongestionAvoidance(
    const QuicSubflowDescriptor& descriptor, QuicPacketLength length) {
  QUIC_LOG(INFO)
      << "LOSS(" << GetOliaParameters(descriptor).id << "," << rtt(descriptor)
          << ") {" << GetOliaParameters(descriptor).l1r << ","
          << GetOliaParameters(descriptor).l2r << "} -> {"
          << GetOliaParameters(descriptor).l2r << ",0}";

  GetOliaParameters(descriptor).l1r = GetOliaParameters(descriptor).l2r;
  GetOliaParameters(descriptor).l2r = 0;
}

QuicByteCount OliaSendAlgorithm::GetMaximumSegmentSize(
    const QuicSubflowDescriptor& descriptor) {
  //TODO(cyrill) get actual maximum segment size for this subflow
  return kDefaultTCPMSS;
}

QuicByteCount OliaSendAlgorithm::GetMinimumSlowStartThreshold(
    const QuicSubflowDescriptor& descriptor) {
  return
      GetNumberOfSubflows() == 1 ?
          2 * GetMaximumSegmentSize(descriptor) :
          GetMaximumSegmentSize(descriptor);
}
QuicByteCount OliaSendAlgorithm::GetMinimumCongestionWindow(
    const QuicSubflowDescriptor& descriptor) {
  return
      GetNumberOfSubflows() == 1 ?
          2 * GetMaximumSegmentSize(descriptor) :
          GetMaximumSegmentSize(descriptor);
}
QuicByteCount OliaSendAlgorithm::CongestionWindowAfterPacketLoss(
    const QuicSubflowDescriptor& descriptor,
    QuicByteCount currentCongestionWindow) {
  QuicByteCount newCongestionWindow = currentCongestionWindow
      * kMultiplicativeDecreaseFactor;
  return std::max(newCongestionWindow, GetMinimumCongestionWindow(descriptor));
}

QuicByteCount& OliaSendAlgorithm::w(const QuicSubflowDescriptor& descriptor) {
  return GetMutableParameters(descriptor).congestion_window;
}
double OliaSendAlgorithm::rtt(const QuicSubflowDescriptor& descriptor) {
  QuicTime::Delta srttDelta =
      GetMutableParameters(descriptor).rtt_stats->smoothed_rtt();
  int64_t rttMicroSeconds;
  if (srttDelta == QuicTime::Delta::Zero()) {
    // Provide fixed initial estimation of rtt
    rttMicroSeconds = kInitialRttMs * kNumMicrosPerMilli;
  } else {
    rttMicroSeconds = srttDelta.ToMicroseconds();
  }
  double srtt = ((double) rttMicroSeconds) / 1000000;
  return srtt;
}
void OliaSendAlgorithm::DeterminePaths() {
  max_w_paths_.clear();
  QuicByteCount w_max = std::numeric_limits<QuicByteCount>::min();
  for (std::pair<QuicSubflowDescriptor, OliaSubflowParameters> p : olia_parameters_) {
    if (w(p.first) > w_max) {
      w_max = w(p.first);
      max_w_paths_.clear();
      max_w_paths_.insert(p.first);
    } else if (w(p.first) == w_max) {
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
bool OliaSendAlgorithm::IsInMaxWPaths(const QuicSubflowDescriptor& descriptor) {
  return max_w_paths_.find(descriptor) != max_w_paths_.end();
}
bool OliaSendAlgorithm::IsInCollectedPaths(
    const QuicSubflowDescriptor& descriptor) {
  return collected_paths_.find(descriptor) != collected_paths_.end();
}
unsigned int OliaSendAlgorithm::NumberOfPaths() {
  return olia_parameters_.size();
}
bool OliaSendAlgorithm::IsCwndLimited(const QuicSubflowDescriptor& descriptor,
    QuicByteCount bytes_in_flight) {
  const QuicByteCount congestion_window = w(descriptor);
  if (bytes_in_flight >= congestion_window) {
    return true;
  }
  const QuicByteCount available_bytes = congestion_window - bytes_in_flight;
  const bool slow_start_limited = InSlowStart(descriptor)
      && bytes_in_flight > congestion_window / 2;
  return slow_start_limited || available_bytes <= kMaxBurstBytes;
}

} // namespace net

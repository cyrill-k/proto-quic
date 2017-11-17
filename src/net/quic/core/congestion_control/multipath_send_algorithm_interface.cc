// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>

#include "net/quic/core/congestion_control/multipath_send_algorithm_interface.h"
#include "net/quic/core/quic_transmission_info.h"
#include "net/quic/core/congestion_control/multipath_scheduler_algorithm.h"

namespace net {

bool MultipathSendAlgorithmInterface::rateBasedSending = false;
bool MultipathSendAlgorithmInterface::noPrr = false;
bool MultipathSendAlgorithmInterface::slowStartLargeReduction = false;

MultipathSendAlgorithmInterface::MultipathSendAlgorithmInterface(
    MultipathSchedulerInterface* scheduler)
    : rate_based_sending_(rateBasedSending), no_prr_(noPrr), slow_start_large_reduction_(
        slowStartLargeReduction), logging_interface_(nullptr), scheduler_(scheduler),
        max_total_bandwidth_(QuicBandwidth::Zero()) {

}

MultipathSendAlgorithmInterface::~MultipathSendAlgorithmInterface() {
}

void MultipathSendAlgorithmInterface::AddSubflow(
    const QuicSubflowDescriptor& subflowDescriptor, RttStats* rttStats,
    QuicUnackedPacketMap* unackedPacketMap) {
  scheduler_->AddSubflow(subflowDescriptor, rttStats);
  SubflowParameters sp(rttStats, unackedPacketMap,
      kInitialCongestionWindowInBytes);
  parameters_[subflowDescriptor] = sp;
}

void MultipathSendAlgorithmInterface::SetPacketHandlingMethod(
    QuicMultipathConfiguration::PacketScheduling packetSchedulingMethod) {
  static_cast<MultipathSchedulerAlgorithm*>(GetScheduler())->SetPacketSchedulingMethod(
      packetSchedulingMethod);
}

void MultipathSendAlgorithmInterface::SetFromConfig(const QuicConfig& config,
    Perspective perspective) {

}

void MultipathSendAlgorithmInterface::SetNumEmulatedConnections(
    int num_connections) {

}

void MultipathSendAlgorithmInterface::MultipathSendAlgorithmInterface::OnConnectionMigration() {

}

void MultipathSendAlgorithmInterface::OnCongestionEvent(
    const QuicSubflowDescriptor& descriptor, bool rtt_updated,
    QuicByteCount prior_in_flight, QuicTime event_time,
    const MultipathSendAlgorithmInterface::CongestionVector& acked_packets,
    const MultipathSendAlgorithmInterface::CongestionVector& lost_packets) {
  Log(descriptor,
      "congestion event: inflight = " + std::to_string(prior_in_flight));
  if (rtt_updated && InSlowStart(descriptor)
      && GetHybridSlowStart(descriptor).ShouldExitSlowStart(
          LatestRtt(descriptor), MinRtt(descriptor),
          GetCongestionWindow(descriptor) / kDefaultTCPMSS)) {
    ExitSlowstart(descriptor);
  }
  if (rtt_updated && logging_interface_ != nullptr) {
    logging_interface_->OnRttUpdated(descriptor, srtt(descriptor));
  }

  for (std::pair<QuicPacketNumber, QuicPacketLength> p : acked_packets) {
    Ack(descriptor, p.first, p.second, prior_in_flight);
  }
  for (std::pair<QuicPacketNumber, QuicPacketLength> p : lost_packets) {
    Loss(descriptor, p.first, p.second, prior_in_flight);
  }
}

bool MultipathSendAlgorithmInterface::OnPacketSent(
    const QuicSubflowDescriptor& descriptor, QuicTime sent_time,
    QuicByteCount bytes_in_flight, QuicPacketNumber packet_number,
    QuicByteCount bytes, HasRetransmittableData is_retransmittable) {
  // Only update bytes_in_flight_ for data packets.
  if (is_retransmittable != HAS_RETRANSMITTABLE_DATA) {
    return false;
  }
  Log(descriptor, "Sent("+std::to_string(packet_number)+")");
  if (InRecovery(descriptor)) {
    // PRR is used when in recovery.
    Prr(descriptor).OnPacketSent(bytes);
  }
  DCHECK_LT(LargestSentPacketNumber(descriptor), packet_number);
  SetLargestSentPacketNumber(descriptor, packet_number);
  GetHybridSlowStart(descriptor).OnPacketSent(packet_number);
  return true;
}

void MultipathSendAlgorithmInterface::Ack(
    const QuicSubflowDescriptor& descriptor, QuicPacketNumber packet_number,
    QuicByteCount bytes_acked, QuicByteCount prior_in_flight) {
  SetLargestAckedPacketNumber(descriptor,
      std::max(packet_number, LargestAckedPacketNumber(descriptor)));

  Log(descriptor, "ack("+std::to_string(packet_number)+")");

  if (InRecovery(descriptor)) {
    if (!no_prr_) {
      // PRR is used when in recovery.
      Prr(descriptor).OnPacketAcked(bytes_acked);
    }
    return;
  }

  // Don't forward ACK to congestion window increase algorithm if InRecovery()
  OnAck(descriptor, bytes_acked);

  setCwnd(descriptor,
      std::max(GetMinimumCongestionWindow(),
          CongestionWindowAfterPacketAck(descriptor, prior_in_flight, bytes_acked)));

  if (InSlowStart(descriptor)) {
    GetHybridSlowStart(descriptor).OnPacketAcked(packet_number);
  }

  if (logging_interface_) {
    logging_interface_->OnAck(descriptor, bytes_acked, cwnd(descriptor),
        InSlowStart(descriptor));
  }
}

void MultipathSendAlgorithmInterface::Loss(
    const QuicSubflowDescriptor& descriptor, QuicPacketNumber packet_number,
    QuicByteCount bytes_lost, QuicByteCount prior_in_flight) {
  // TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
  // already sent should be treated as a single loss event, since it's expected.
  if (packet_number <= LargestSentAtLastCutback(descriptor)) {
    Log(descriptor, "Ignoring loss(" + std::to_string(packet_number) + ")");
    if (LastCutbackExitedSlowstart(descriptor)) {
      if (slow_start_large_reduction_) {
        Log(descriptor, "Reduce congestion window by "+std::to_string(bytes_lost));
        // Reduce congestion window by lost_bytes for every loss.
        setCwnd(descriptor,
            std::max(cwnd(descriptor) - bytes_lost,
                MinSlowStartExitWindow(descriptor)));
        setSsthresh(descriptor, cwnd(descriptor));
      }
    }
    QUIC_DVLOG(1)
        << "Ignoring loss for largest_missing:" << packet_number
            << " because it was sent prior to the last CWND cutback.";
    return;
  }

  Log(descriptor, "loss(" + std::to_string(packet_number) +")");

  SetLastCutbackExitedSlowstart(descriptor, InSlowStart(descriptor));

  if (!no_prr_) {
    Prr(descriptor).OnPacketLost(prior_in_flight);
  }

  QuicByteCount newCwnd;
  if (slow_start_large_reduction_ && InSlowStart(descriptor)) {
    DCHECK_LT(kDefaultTCPMSS, cwnd(descriptor));
    if (cwnd(descriptor) >= 2 * kInitialCongestionWindowInBytes) {
      SetMinSlowStartExitWindow(descriptor, cwnd(descriptor) / 2);
    }
    newCwnd = cwnd(descriptor) - kDefaultTCPMSS;
  } else {
    newCwnd = CongestionWindowAfterPacketLoss(descriptor);
  }
  setCwnd(descriptor, std::max(newCwnd, GetMinimumCongestionWindow()));
  setSsthresh(descriptor, std::max(cwnd(descriptor), GetMinimumSlowStartThreshold()));
  SetLargestSentAtLastCutback(descriptor, LargestSentPacketNumber(descriptor));

  if (logging_interface_) {
    logging_interface_->OnLoss(descriptor, bytes_lost, cwnd(descriptor));
  }
}

void MultipathSendAlgorithmInterface::OnRetransmissionTimeout(
    const QuicSubflowDescriptor& descriptor, bool packets_retransmitted) {
  SetLargestSentAtLastCutback(descriptor, 0);
  if (!packets_retransmitted) {
    return;
  }
  GetHybridSlowStart(descriptor).Restart();

  setSsthresh(descriptor,
      std::max(cwnd(descriptor) / 2, GetMinimumSlowStartThreshold()));
  setCwnd(descriptor, std::max(GetMinimumCongestionWindow(), ssthresh(descriptor)));
}

QuicTime::Delta MultipathSendAlgorithmInterface::TimeUntilSend(
    const QuicSubflowDescriptor& descriptor, QuicTime now,
    QuicByteCount bytes_in_flight) {
  Log(descriptor, "timeuntilsend bytes_in_flight = " + std::to_string(bytes_in_flight));
  if (!no_prr_ && InRecovery(descriptor)) {
    // PRR is used when in recovery.
    QuicTime::Delta delay = Prr(descriptor).TimeUntilSend(cwnd(descriptor),
        bytes_in_flight, ssthresh(descriptor));
    Log(descriptor, "prr timeuntilsend = " + delay.ToDebugValue());
    return delay;
  }
  if (cwnd(descriptor) > bytes_in_flight) {
    Log(descriptor, "timeuntilsend: cwnd > inflight");
    return QuicTime::Delta::Zero();
  }
  //if (min4_mode_ && bytes_in_flight < 4 * kDefaultTCPMSS) {
  //  return QuicTime::Delta::Zero();
  //}
  if (rate_based_sending_
      && cwnd(descriptor) * kRateBasedExtraCwnd > bytes_in_flight) {
    Log(descriptor, "timeuntilsend(rate based): cwnd *1.5 > inflight");
    return QuicTime::Delta::Zero();
  }
  Log(descriptor, "timeuntilsend: inf");
  return QuicTime::Delta::Infinite();
}

QuicBandwidth MultipathSendAlgorithmInterface::PacingRate(
    const QuicSubflowDescriptor& descriptor,
    QuicByteCount bytes_in_flight) const {
  // We pace at twice the rate of the underlying sender's bandwidth estimate
  // during slow start and 1.25x during congestion avoidance to ensure pacing
  // doesn't prevent us from filling the window.
  QuicTime::Delta rtt = srtt(descriptor);
  if (rtt.IsZero()) {
    rtt = InitialRtt(descriptor);
  }
  const QuicBandwidth bandwidth = QuicBandwidth::FromBytesAndTimeDelta(
      cwnd(descriptor), rtt);
  if (rate_based_sending_ && bytes_in_flight > cwnd(descriptor)) {
    // Rate based sending allows sending more than CWND, but reduces the pacing
    // rate when the bytes in flight is more than the CWND to 75% of bandwidth.
    return 0.75 * bandwidth;
  }
  return bandwidth
      * (InSlowStart(descriptor) ?
          2 : (no_prr_ && InRecovery(descriptor) ? 1 : 1.25));
}

QuicBandwidth MultipathSendAlgorithmInterface::BandwidthEstimate(
    const QuicSubflowDescriptor& descriptor) const {
  if(!descriptor.IsInitialized()) {
    return QuicBandwidth::Zero();
  }
  QuicTime::Delta rtt = srtt(descriptor);
  if (rtt.IsZero()) {
    // If we haven't measured an rtt, the bandwidth estimate is unknown.
    return QuicBandwidth::Zero();
  }
  return QuicBandwidth::FromBytesAndTimeDelta(cwnd(descriptor), rtt);
}

QuicByteCount MultipathSendAlgorithmInterface::GetCongestionWindow(
    const QuicSubflowDescriptor& descriptor) const {
  if (!descriptor.IsInitialized()) {
    return std::accumulate(parameters_.begin(), parameters_.end(), 0,
        [](size_t val, std::pair<const QuicSubflowDescriptor, SubflowParameters> it) {
          return it.second.congestion_window + val;
        });
  } else {
    DCHECK(TracksDescriptor(descriptor));
    return cwnd(descriptor);
  }
}

bool MultipathSendAlgorithmInterface::InSlowStart(
    const QuicSubflowDescriptor& descriptor) const {
  DCHECK(TracksDescriptor(descriptor));
  return cwnd(descriptor) < ssthresh(descriptor);
}

bool MultipathSendAlgorithmInterface::InRecovery(
    const QuicSubflowDescriptor& descriptor) const {
  DCHECK(TracksDescriptor(descriptor));
  return LargestAckedPacketNumber(descriptor)
      <= LargestSentAtLastCutback(descriptor)
      && LargestAckedPacketNumber(descriptor) != 0;
}

QuicByteCount MultipathSendAlgorithmInterface::GetSlowStartThreshold(
    const QuicSubflowDescriptor& descriptor) const {
  DCHECK(TracksDescriptor(descriptor));
  return ssthresh(descriptor);
}

CongestionControlType MultipathSendAlgorithmInterface::GetCongestionControlType() const {
  return CongestionControlType::kCubic;
}

void MultipathSendAlgorithmInterface::ResumeConnectionState(
    const CachedNetworkParameters& cached_network_params,
    bool max_bandwidth_resumption) {

}

std::string MultipathSendAlgorithmInterface::GetDebugState() const {
  return "";
}

void MultipathSendAlgorithmInterface::OnApplicationLimited(
    QuicByteCount bytes_in_flight) {

}

QuicByteCount MultipathSendAlgorithmInterface::GetMinimumCongestionWindow() const {
  return 8 * kDefaultTCPMSS;
  //return GetNumberOfSubflows() == 1 ? 2 * kDefaultTCPMSS : kDefaultTCPMSS;
}

QuicByteCount MultipathSendAlgorithmInterface::GetMinimumSlowStartThreshold() const {
  return GetMinimumCongestionWindow();
}

bool MultipathSendAlgorithmInterface::IsCwndLimited(
    const QuicSubflowDescriptor& descriptor,
    QuicByteCount bytes_in_flight) const {
  const QuicByteCount congestion_window = cwnd(descriptor);
  if (bytes_in_flight >= congestion_window) {
    return true;
  }
  const QuicByteCount available_bytes = congestion_window - bytes_in_flight;
  const bool slow_start_limited = InSlowStart(descriptor)
      && bytes_in_flight > congestion_window / 2;
  return slow_start_limited || available_bytes <= kMaxBurstBytes;
}

QuicByteCount MultipathSendAlgorithmInterface::ssthresh(
    const QuicSubflowDescriptor& descriptor) const {
  return GetParameters(descriptor).ssthresh;
}

void MultipathSendAlgorithmInterface::setSsthresh(
    const QuicSubflowDescriptor& descriptor, QuicByteCount newSsthresh) {
  GetMutableParameters(descriptor).ssthresh = newSsthresh;
}

QuicByteCount MultipathSendAlgorithmInterface::cwnd(
    const QuicSubflowDescriptor& descriptor) const {
  return GetParameters(descriptor).congestion_window;
}

void MultipathSendAlgorithmInterface::Log(
    const QuicSubflowDescriptor& descriptor, std::string s, bool forceLogging) {
  if(forceLogging || false) QUIC_LOG(WARNING)
      << descriptor.ToString() << "MPSAI("
          << (InSlowStart(descriptor) ?
              "SS" : (InRecovery(descriptor) ? "RE" : "CA")) << "): cwnd="
          << cwnd(descriptor) << ", ssthresh=" << ssthresh(descriptor) << ": "
          << s;
}

void MultipathSendAlgorithmInterface::setCwnd(
    const QuicSubflowDescriptor& descriptor, QuicByteCount newCwnd) {
  DCHECK(newCwnd >= GetMinimumCongestionWindow());
  GetMutableParameters(descriptor).congestion_window = newCwnd;
  Log(descriptor, "setcwnd");
}

QuicTime::Delta MultipathSendAlgorithmInterface::srtt(
    const QuicSubflowDescriptor& descriptor) const {
  return GetParameters(descriptor).rtt_stats->smoothed_rtt();
}
QuicTime::Delta MultipathSendAlgorithmInterface::MinRtt(
    const QuicSubflowDescriptor& descriptor) const {
  return GetParameters(descriptor).rtt_stats->min_rtt();
}
QuicTime::Delta MultipathSendAlgorithmInterface::LatestRtt(
    const QuicSubflowDescriptor& descriptor) const {
  return GetParameters(descriptor).rtt_stats->latest_rtt();
}
QuicTime::Delta MultipathSendAlgorithmInterface::InitialRtt(
    const QuicSubflowDescriptor& descriptor) const {
  return QuicTime::Delta::FromMicroseconds(
      GetParameters(descriptor).rtt_stats->initial_rtt_us());
}
HybridSlowStart MultipathSendAlgorithmInterface::GetHybridSlowStart(
    const QuicSubflowDescriptor& descriptor) {
  return GetMutableParameters(descriptor).hybrid_slow_start;
}
PrrSender MultipathSendAlgorithmInterface::Prr(
    const QuicSubflowDescriptor& descriptor) {
  return GetMutableParameters(descriptor).prr;
}
QuicPacketNumber MultipathSendAlgorithmInterface::LargestSentPacketNumber(
    const QuicSubflowDescriptor& descriptor) const {
  return GetParameters(descriptor).largest_sent_packet_number;
}
void MultipathSendAlgorithmInterface::SetLargestSentPacketNumber(
    const QuicSubflowDescriptor& descriptor, QuicPacketNumber packetNumber) {
  GetMutableParameters(descriptor).largest_sent_packet_number = packetNumber;
}
QuicPacketNumber MultipathSendAlgorithmInterface::LargestAckedPacketNumber(
    const QuicSubflowDescriptor& descriptor) const {
  return GetParameters(descriptor).largest_acked_packet_number;
}
void MultipathSendAlgorithmInterface::SetLargestAckedPacketNumber(
    const QuicSubflowDescriptor& descriptor, QuicPacketNumber packetNumber) {
  Log(descriptor, "largest acked = "+std::to_string(packetNumber));
  GetMutableParameters(descriptor).largest_acked_packet_number = packetNumber;
}
QuicPacketNumber MultipathSendAlgorithmInterface::LargestSentAtLastCutback(
    const QuicSubflowDescriptor& descriptor) const {
  return GetParameters(descriptor).largest_sent_at_last_cutback;
}
void MultipathSendAlgorithmInterface::SetLargestSentAtLastCutback(
    const QuicSubflowDescriptor& descriptor, QuicPacketNumber packetNumber) {
  Log(descriptor, "largest sent at last cutback set to: " + std::to_string(packetNumber));
  GetMutableParameters(descriptor).largest_sent_at_last_cutback = packetNumber;
}
bool MultipathSendAlgorithmInterface::LastCutbackExitedSlowstart(
    const QuicSubflowDescriptor& descriptor) const {
  return GetParameters(descriptor).last_cutback_exited_slowstart;
}
void MultipathSendAlgorithmInterface::SetLastCutbackExitedSlowstart(
    const QuicSubflowDescriptor& descriptor, bool val) {
  GetMutableParameters(descriptor).last_cutback_exited_slowstart = val;
}
QuicByteCount MultipathSendAlgorithmInterface::MinSlowStartExitWindow(
    const QuicSubflowDescriptor& descriptor) const {
  return GetParameters(descriptor).min_slow_start_exit_window;
}
void MultipathSendAlgorithmInterface::SetMinSlowStartExitWindow(
    const QuicSubflowDescriptor& descriptor, QuicByteCount window) {
  GetMutableParameters(descriptor).min_slow_start_exit_window = window;
}

QuicSubflowDescriptor MultipathSendAlgorithmInterface::GetNextStreamFrameSubflow(
    QuicStreamId streamId, size_t length, const QuicSubflowDescriptor& hint,
    SendReason reason) {
  // Always send unencrypted packets on the subflow they belong.
  if (reason == UNENCRYPTED_TRANSMISSION) {
    DCHECK(hint.IsInitialized());
    return hint;
  }
  // Always send crypto packets belonging to a sublfow on this subflow.
  if(streamId == 1 && hint.IsInitialized()) {
    return hint;
  }
  QuicSubflowDescriptor descriptor = GetNextSubflow(length,
      !HasForwardSecureSubflow());
  return descriptor;
}

QuicSubflowDescriptor MultipathSendAlgorithmInterface::GetNextControlFrameSubflow(
    const QuicFrame& frame, const QuicSubflowDescriptor& hint) {
  QuicSubflowDescriptor descriptor;
  // Always send control frames on the subflow that issued them.
  if (hint.IsInitialized()) {
    descriptor = hint;
  } else {
    descriptor = GetNextSubflow(max_frame_length, !HasForwardSecureSubflow());
  }

  return descriptor;
}

QuicSubflowDescriptor MultipathSendAlgorithmInterface::GetNextRetransmissionSubflow(
    const QuicTransmissionInfo& transmission_info,
    const QuicSubflowDescriptor& hint) {
  // Always retransmit unencrypted and 0-RTT packets on the same subflow
  if (transmission_info.encryption_level != ENCRYPTION_FORWARD_SECURE) {
    DCHECK(hint.IsInitialized());
    return hint;
  }
  QuicSubflowDescriptor descriptor = GetNextSubflow(
      transmission_info.bytes_sent, !HasForwardSecureSubflow());
  return descriptor;
}

std::list<QuicSubflowDescriptor> MultipathSendAlgorithmInterface::AppendAckFrames(
    const QuicSubflowDescriptor& packetSubflowDescriptor) {
  return scheduler_->GetAckFramePriority(packetSubflowDescriptor);
}
void MultipathSendAlgorithmInterface::AckFramesAppended(
    const std::list<QuicSubflowDescriptor>& ackFrameSubflowDescriptors) {
  scheduler_->AckFramesAppended(ackFrameSubflowDescriptors);
}

void MultipathSendAlgorithmInterface::OnAckFrameUpdated(
    const QuicSubflowDescriptor& subflowDescriptor) {
  scheduler_->OnAckFrameUpdated(subflowDescriptor);
}

void MultipathSendAlgorithmInterface::InitialEncryptionEstablished(
    const QuicSubflowDescriptor& descriptor) {
  parameters_[descriptor].encryption_level = ENCRYPTION_INITIAL;
}

void MultipathSendAlgorithmInterface::ForwardSecureEncryptionEstablished(
    const QuicSubflowDescriptor& descriptor) {
  parameters_[descriptor].forward_secure_encryption_established = true;
  parameters_[descriptor].encryption_level = ENCRYPTION_FORWARD_SECURE;
}

EncryptionLevel MultipathSendAlgorithmInterface::GetEncryptionLevel(
    const QuicSubflowDescriptor& descriptor) {
  return parameters_[descriptor].encryption_level;
}

bool MultipathSendAlgorithmInterface::HasForwardSecureSubflow() {
  return std::any_of(parameters_.begin(), parameters_.end(),
      [](std::pair<const QuicSubflowDescriptor, SubflowParameters> p) {return p.second.encryption_level == ENCRYPTION_FORWARD_SECURE;});
}
bool MultipathSendAlgorithmInterface::FitsCongestionWindow(
    const QuicSubflowDescriptor& descriptor, QuicPacketLength length) {
  QUIC_LOG(INFO)
      << "param[].in_flight = "
          << parameters_[descriptor].unacked_packet_map->bytes_in_flight()
          << " < param[].congestion_window = "
          << parameters_[descriptor].congestion_window;
  return parameters_[descriptor].unacked_packet_map->bytes_in_flight()
      < parameters_[descriptor].congestion_window;
}
bool MultipathSendAlgorithmInterface::IsForwardSecure(
    const QuicSubflowDescriptor& descriptor) {
  return parameters_[descriptor].encryption_level == ENCRYPTION_FORWARD_SECURE;
}
bool MultipathSendAlgorithmInterface::IsInitialSecure(
    const QuicSubflowDescriptor& descriptor) {
  return parameters_[descriptor].encryption_level == ENCRYPTION_INITIAL;
}
void MultipathSendAlgorithmInterface::SentOnSubflow(
    const QuicSubflowDescriptor& descriptor, QuicPacketLength length) {
  scheduler_->UsedSubflow(descriptor);
}
bool MultipathSendAlgorithmInterface::GetNumberOfSubflows() const {
  return parameters_.size();
}
QuicSubflowDescriptor MultipathSendAlgorithmInterface::GetNextSubflow(
    QuicPacketLength length, bool allowInitialEncryption) {
  QuicSubflowDescriptor fwFitting, fw, initialFitting, initial;
  int k = 0;
  for (const QuicSubflowDescriptor& descriptor : scheduler_->GetSubflowPriority()) {
    QUIC_LOG(INFO)
        << "desc(" << k++ << "): " << descriptor.ToString() << ": fit = "
            << FitsCongestionWindow(descriptor, length) << " fwsec = "
            << IsForwardSecure(descriptor) << " initsec = "
            << IsInitialSecure(descriptor);

    if (!fwFitting.IsInitialized() && FitsCongestionWindow(descriptor, length)
        && IsForwardSecure(descriptor)) {
      fwFitting = descriptor;
    }
    if (!fw.IsInitialized() && IsForwardSecure(descriptor)) {
      fw = descriptor;
    }
    if (!initialFitting.IsInitialized()
        && FitsCongestionWindow(descriptor, length)
        && IsInitialSecure(descriptor)) {
      initialFitting = descriptor;
    }
    if (!initial.IsInitialized() && IsInitialSecure(descriptor)) {
      initial = descriptor;
    }
  }

  if (fwFitting.IsInitialized()) {
    QUIC_LOG(INFO) << "choosing fw fitting: " << fwFitting.ToString();
    return fwFitting;
  }
  if (allowInitialEncryption && initialFitting.IsInitialized()) {
    QUIC_LOG(INFO) << "choosing initial fitting: " << initialFitting.ToString();
    return initialFitting;
  }
  if (fw.IsInitialized()) {
    QUIC_LOG(INFO) << "choosing fw NON fitting: " << fw.ToString();
    return fw;
  }
  if (allowInitialEncryption && initial.IsInitialized()) {
    QUIC_LOG(INFO) << "choosing init NON fitting: " << initial.ToString();
    return initial;
  }
  // should never reach here
  DCHECK(false);
  return QuicSubflowDescriptor();
}

QuicSubflowDescriptor MultipathSendAlgorithmInterface::GetNextForwardSecureSubflow() {
  std::list<QuicSubflowDescriptor> subflowPriority =
      scheduler_->GetSubflowPriority();
  for (const QuicSubflowDescriptor& descriptor : subflowPriority) {
    QUIC_LOG(INFO)
        << descriptor.ToString() << " fw = "
            << parameters_[descriptor].forward_secure_encryption_established;
    if (parameters_[descriptor].forward_secure_encryption_established) {
      return descriptor;
    }
  }
  return uninitialized_subflow_descriptor_;
}

void MultipathSendAlgorithmInterface::ExitSlowstart(
    const QuicSubflowDescriptor& descriptor) {
  GetMutableParameters(descriptor).ssthresh =
      GetParameters(descriptor).congestion_window;
}

MultipathSendAlgorithmInterface::SubflowParameters::SubflowParameters() {
}
MultipathSendAlgorithmInterface::SubflowParameters::SubflowParameters(
    RttStats* rttStats, QuicUnackedPacketMap* unackedPacketMap,
    QuicByteCount initialCongestionWindow)
    : rtt_stats(rttStats), unacked_packet_map(unackedPacketMap), congestion_window(
        initialCongestionWindow), congestion_state(
        SUBFLOW_CONGESTION_SLOWSTART), forward_secure_encryption_established(
        false), encryption_level(ENCRYPTION_NONE), in_slow_start(false), ssthresh(
        std::numeric_limits<QuicByteCount>::max()), hybrid_slow_start(), prr(), largest_sent_packet_number(
        0), largest_acked_packet_number(0), largest_sent_at_last_cutback(0), last_cutback_exited_slowstart(
        false), min_slow_start_exit_window(initialCongestionWindow) {
}
MultipathSendAlgorithmInterface::SubflowParameters::SubflowParameters(
    const SubflowParameters& other)
    : rtt_stats(other.rtt_stats), unacked_packet_map(other.unacked_packet_map), congestion_window(
        other.congestion_window), congestion_state(other.congestion_state), forward_secure_encryption_established(
        other.forward_secure_encryption_established), encryption_level(
        other.encryption_level), in_slow_start(other.in_slow_start), ssthresh(
        other.ssthresh), hybrid_slow_start(other.hybrid_slow_start), prr(
        other.prr), largest_sent_packet_number(
        other.largest_sent_packet_number), largest_acked_packet_number(
        other.largest_acked_packet_number), largest_sent_at_last_cutback(
        other.largest_sent_at_last_cutback), last_cutback_exited_slowstart(
        other.last_cutback_exited_slowstart), min_slow_start_exit_window(
        other.min_slow_start_exit_window) {
}

} // namespace net

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_connection_manager_logger.h"

#include <string>
#include "net/quic/core/quic_types.h"

namespace net {

QuicConnectionManagerLogger::QuicConnectionManagerLogger(std::string logfile,
    const QuicClock* clock, QuicConnectionResolver* connectionResolver)
    : clock_(clock), start_time_(QuicTime::Zero()), last_interval_log_(
        QuicTime::Zero()), connection_resolver_(connectionResolver) {

}

QuicConnectionManagerLogger::~QuicConnectionManagerLogger() {
  LogFullStatistic(clock_->Now());
}

void QuicConnectionManagerLogger::OnPacketSent(QuicConnection* connection,
    QuicPacketNumber packetNumber, QuicPacketLength packetLength) {
  QuicSubflowId id = connection->GetSubflowId();
  if (id == 0)
    return;

  interval_statistics_[id].nPacketsSent++;
  full_statistics_[id].nPacketsSent++;
  interval_statistics_[id].nBytesSent += packetLength;
  full_statistics_[id].nBytesSent += packetLength;

  RecordEvent(EVENT_PACKET_SENT, id,
      "[" + std::to_string(packetNumber) + "]: "
          + std::to_string(packetLength));
}

void QuicConnectionManagerLogger::OnPacketReceived(QuicConnection* connection,
    QuicPacketNumber packetNumber, QuicPacketLength packetLength) {
  QuicSubflowId id = connection->GetSubflowId();
  if (id == 0)
    return;

  interval_statistics_[id].nPacketsReceived++;
  full_statistics_[id].nPacketsReceived++;

  RecordEvent(EVENT_PACKET_RECEIVED, id,
      "[" + std::to_string(packetNumber) + "]: "
          + std::to_string(packetLength));
}

void QuicConnectionManagerLogger::OnPacketLost(QuicConnection* connection,
    QuicPacketNumber packetNumber, QuicPacketLength packetLength,
    TransmissionType transmissionType) {
  QuicSubflowId id = connection->GetSubflowId();
  if (id == 0)
    return;

  interval_statistics_[id].nPacketsLost++;
  full_statistics_[id].nPacketsLost++;
  interval_statistics_[id].nBytesLost += packetLength;
  full_statistics_[id].nBytesLost += packetLength;

  std::string transmissionTypeString;
  switch (transmissionType) {
  case TLP_RETRANSMISSION:
    transmissionTypeString = "TLP";
    break;
  case LOSS_RETRANSMISSION:
    transmissionTypeString = "LOSS";
    break;
  default:
    transmissionTypeString = "UNKNOWN_TRANSMISSION";
    break;
  }
  RecordEvent(EVENT_PACKET_LOST, id,
      "[" + std::to_string(packetNumber) + "]: " + std::to_string(packetLength)
          + "," + transmissionTypeString);
}

void QuicConnectionManagerLogger::OnAckSent(QuicConnection* connection,
    QuicPacketLength ackLength) {
  QuicSubflowId id = connection->GetSubflowId();
  if (id == 0)
    return;

  interval_statistics_[id].nAcksSent++;
  full_statistics_[id].nAcksSent++;
  interval_statistics_[id].nAckBytesSent += ackLength;
  full_statistics_[id].nAckBytesSent += ackLength;

  std::string s = std::to_string(ackLength);
  RecordEvent(EVENT_ACK_SENT, id, s);
}

void QuicConnectionManagerLogger::OnAckReceived(QuicConnection* connection,
    QuicPacketNumber packetNumber, QuicPacketLength packetLength,
    QuicTime::Delta ackDelayTime, QuicTime::Delta rtt) {
  QuicSubflowId id = connection->GetSubflowId();
  if (id == 0)
    return;

  interval_statistics_[id].nPacketsAcked++;
  full_statistics_[id].nPacketsAcked++;
  interval_statistics_[id].nBytesAcked += packetLength;
  full_statistics_[id].nBytesAcked += packetLength;
  interval_statistics_[id].sumAckDelayTime += ackDelayTime.ToMicroseconds();
  full_statistics_[id].sumAckDelayTime += ackDelayTime.ToMicroseconds();
  interval_statistics_[id].sumRtt += rtt.ToMicroseconds();
  full_statistics_[id].sumRtt += rtt.ToMicroseconds();

  RecordEvent(EVENT_ACK_RECEIVED, id,
      "[" + std::to_string(packetNumber) + "]: " + std::to_string(packetLength)
          + "," + std::to_string(ackDelayTime.ToMicroseconds()) + ","
          + std::to_string(rtt.ToMicroseconds()));
}

void QuicConnectionManagerLogger::OnStreamFrameSent(QuicConnection* connection,
    QuicStreamId streamId, QuicByteCount length) {
  QuicSubflowId id = connection->GetSubflowId();
  if (id == 0)
    return;

  interval_statistics_[id].nStreamFramesSent++;
  full_statistics_[id].nStreamFramesSent++;
  interval_statistics_[id].nStreamBytesSent += length;
  full_statistics_[id].nStreamBytesSent += length;

  std::string s = std::to_string(length);
  RecordEvent(EVENT_STREAM_SENT, id, s);
}

void QuicConnectionManagerLogger::OnStreamFrameReceived(
    QuicConnection* connection, QuicStreamId streamId, QuicByteCount length) {
  QuicSubflowId id = connection->GetSubflowId();
  if (id == 0)
    return;

  interval_statistics_[id].nStreamFramesReceived++;
  full_statistics_[id].nStreamFramesReceived++;
  interval_statistics_[id].nStreamBytesReceived += length;
  full_statistics_[id].nStreamBytesReceived += length;

  std::string s = std::to_string(length);
  RecordEvent(EVENT_STREAM_RECEIVED, id, s);
}

void QuicConnectionManagerLogger::OnLoss(
    const QuicSubflowDescriptor& subflowDescriptor,
    QuicPacketLength packetLength, QuicByteCount newCongestionWindow) {
  QuicSubflowId id = connection_resolver_->GetSubflowId(subflowDescriptor);
  if (id == 0)
    return;

  std::string s = std::to_string(packetLength) + ","
      + std::to_string(newCongestionWindow);
  RecordEvent(EVENT_LOSS_ALGORITHM_LOSS, id, s);
}

void QuicConnectionManagerLogger::OnAck(
    const QuicSubflowDescriptor& subflowDescriptor,
    QuicPacketLength packetLength, QuicByteCount newCongestionWindow) {
  QuicSubflowId id = connection_resolver_->GetSubflowId(subflowDescriptor);
  if (id == 0)
    return;

  std::string s = std::to_string(packetLength) + ","
      + std::to_string(newCongestionWindow);
  RecordEvent(EVENT_LOSS_ALGORITHM_ACK, id, s);
}

void QuicConnectionManagerLogger::OnRttUpdated(
    const QuicSubflowDescriptor& subflowDescriptor, QuicTime::Delta newRtt) {
  QuicSubflowId id = connection_resolver_->GetSubflowId(subflowDescriptor);
  if (id == 0)
    return;

  std::string s = std::to_string(newRtt.ToMicroseconds());
  RecordEvent(EVENT_LOSS_ALGORITHM_RTT, id, s);
}

void QuicConnectionManagerLogger::RecordEvent(std::string eventType,
    QuicSubflowId id, std::string content) {
  if (id == 0)
    return;

  QUIC_LOG(INFO) << id << " " << eventType << ": " << content;

  QuicTime now = clock_->Now();
  // Initialize the log interval times
  if (last_interval_log_ == QuicTime::Zero()) {
    last_interval_log_ = now;
    start_time_ = now;
  }
  if (now - last_interval_log_ > log_interval_) {
    LogIntervalStatistic(now);
    LogFullStatistic(now);
    last_interval_log_ = now;

    // clear statistics for next interval
    for (std::pair<QuicSubflowId, Statistic> p : interval_statistics_) {
      interval_statistics_[p.first] = Statistic();
    }
  }
}

void QuicConnectionManagerLogger::LogStatistic(std::string prefix, Statistic s,
    QuicTime::Delta delta) {
  DCHECK(delta.ToMicroseconds() != 0);
  uint64_t sent_bps = s.nBytesSent
      / ((double) delta.ToMicroseconds() / 1000000);
  uint64_t lost_bps = s.nBytesLost
      / ((double) delta.ToMicroseconds() / 1000000);
  uint64_t ack_sent_bps = s.nAckBytesSent
      / ((double) delta.ToMicroseconds() / 1000000);
  uint64_t ack_rcv_bps = s.nBytesAcked
      / ((double) delta.ToMicroseconds() / 1000000);
  uint64_t ack_del_bps =
      s.nPacketsAcked == 0 ? 0 : s.sumAckDelayTime / s.nPacketsAcked;
  uint64_t ack_rtt_bps = s.nPacketsAcked == 0 ? 0 : s.sumRtt / s.nPacketsAcked;
  uint64_t str_sent_bps = s.nStreamBytesSent
      / ((double) delta.ToMicroseconds() / 1000000);
  uint64_t str_rcv_bps = s.nStreamBytesReceived
      / ((double) delta.ToMicroseconds() / 1000000);

  QUIC_LOG(INFO)
      << prefix << "mu=" << delta.ToMicroseconds() << " sent["
          << std::to_string(s.nPacketsSent) << "/" << s.nBytesSent << "]="
          << std::to_string(sent_bps) << " received["
          << std::to_string(s.nPacketsReceived) << "] lost["
          << std::to_string(s.nPacketsLost) << "/" << s.nBytesLost << "]="
          << std::to_string(lost_bps) << " acksent["
          << std::to_string(s.nAcksSent) << "/" << s.nAckBytesSent << "]="
          << std::to_string(ack_sent_bps) << " ackrcv["
          << std::to_string(s.nPacketsAcked) << "/" << s.nBytesAcked << "]="
          << std::to_string(ack_rcv_bps) << "," << std::to_string(ack_del_bps)
          << "," << std::to_string(ack_rtt_bps) << " str_sent["
          << std::to_string(s.nStreamFramesSent) << "/" << s.nStreamBytesSent
          << "]=" << std::to_string(str_sent_bps) << " str_received["
          << std::to_string(s.nStreamFramesReceived) << "/"
          << s.nStreamBytesReceived << "]=" << std::to_string(str_rcv_bps);
}

void QuicConnectionManagerLogger::LogIntervalStatistic(QuicTime t) {
  for (std::pair<QuicSubflowId, Statistic> p : interval_statistics_) {
    LogStatistic(std::to_string(p.first) + " (interval): ", p.second,
        t - last_interval_log_);
  }
}

void QuicConnectionManagerLogger::LogFullStatistic(QuicTime t) {
  for (std::pair<QuicSubflowId, Statistic> p : full_statistics_) {
    LogStatistic(std::to_string(p.first) + " (full): ", p.second,
        t - start_time_);
  }
}

QuicConnectionManagerLogger::Statistic::Statistic()
    : nPacketsSent(0), nBytesSent(0), nPacketsReceived(0), nPacketsLost(0), nBytesLost(
        0), nPacketsAcked(0), nBytesAcked(0), sumAckDelayTime(0), sumRtt(0), nAcksSent(
        0), nAckBytesSent(0), nStreamFramesSent(0), nStreamBytesSent(0), nStreamFramesReceived(
        0), nStreamBytesReceived(0) {
}

QuicConnectionManagerLogger::Statistic::Statistic(const Statistic& other)
    : nPacketsSent(other.nPacketsSent), nBytesSent(other.nBytesSent), nPacketsReceived(
        other.nPacketsReceived), nPacketsLost(other.nPacketsLost), nBytesLost(
        other.nBytesLost), nPacketsAcked(other.nPacketsAcked), nBytesAcked(
        other.nBytesAcked), sumAckDelayTime(other.sumAckDelayTime), sumRtt(
        other.sumRtt), nAcksSent(other.nAcksSent), nAckBytesSent(
        other.nAckBytesSent), nStreamFramesSent(other.nStreamFramesSent), nStreamBytesSent(
        other.nStreamBytesSent), nStreamFramesReceived(
        other.nStreamFramesReceived), nStreamBytesReceived(
        other.nStreamBytesReceived) {
}

} // namespace net

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_connection_manager_logger.h"

#include <string>
#include "net/quic/core/quic_types.h"

namespace net {

QuicConnectionManagerLogger::QuicConnectionManagerLogger(std::string logfile,
    const QuicClock* clock)
    : clock_(clock), start_time_(QuicTime::Zero()), last_interval_log_(QuicTime::Zero()) {

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

  RecordEvent(EVENT_PACKET_SENT, connection,
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

  RecordEvent(EVENT_PACKET_RECEIVED, connection,
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
  RecordEvent(EVENT_PACKET_LOST, connection,
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
  RecordEvent(EVENT_ACK_SENT, connection, s);
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

  RecordEvent(EVENT_ACK_RECEIVED, connection,
      "[" + std::to_string(packetNumber) + "]: " + std::to_string(packetLength)
          + "," + std::to_string(ackDelayTime.ToMicroseconds()) + ","
          + std::to_string(rtt.ToMicroseconds()));
}

void QuicConnectionManagerLogger::RecordEvent(std::string eventType,
    QuicConnection* connection, std::string content) {
  QuicSubflowId id = connection->GetSubflowId();
  if (id == 0)
    return;

  QUIC_LOG(INFO)
      << connection->GetSubflowId() << " " << eventType << ": " << content;

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

  QUIC_LOG(INFO)
      << prefix << "sent[" << std::to_string(s.nPacketsSent) << "]="
          << std::to_string(sent_bps) << " received["
          << std::to_string(s.nPacketsReceived) << "] lost["
          << std::to_string(s.nPacketsLost) << "]=" << std::to_string(lost_bps)
          << " acksent[" << std::to_string(s.nAcksSent) << "]="
          << std::to_string(ack_sent_bps) << " ackrcv["
          << std::to_string(s.nPacketsAcked) << "]="
          << std::to_string(ack_rcv_bps) << "," << std::to_string(ack_del_bps)
          << "," << std::to_string(ack_rtt_bps);
}

void QuicConnectionManagerLogger::LogIntervalStatistic(QuicTime t) {
  for (std::pair<QuicSubflowId, Statistic> p : interval_statistics_) {
    LogStatistic(std::to_string(p.first) + " (interval): ", p.second,
        t-last_interval_log_);
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
        0), nAckBytesSent(0) {
}

QuicConnectionManagerLogger::Statistic::Statistic(const Statistic& other)
    : nPacketsSent(other.nPacketsSent), nBytesSent(other.nBytesSent), nPacketsReceived(
        other.nPacketsReceived), nPacketsLost(other.nPacketsLost), nBytesLost(
        other.nBytesLost), nPacketsAcked(other.nPacketsAcked), nBytesAcked(
        other.nBytesAcked), sumAckDelayTime(other.sumAckDelayTime), sumRtt(
        other.sumRtt), nAcksSent(other.nAcksSent), nAckBytesSent(
        other.nAckBytesSent) {
}

} // namespace net

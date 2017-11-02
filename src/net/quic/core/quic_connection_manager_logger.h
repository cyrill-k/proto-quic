// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This class receives callbacks from the QuicConnection and logs
// relevant events.

#ifndef NET_QUIC_CORE_QUIC_CONNECTION_MANAGER_LOGGER_H_
#define NET_QUIC_CORE_QUIC_CONNECTION_MANAGER_LOGGER_H_

#include "base/macros.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_connection_resolver.h"

namespace net {

class QUIC_EXPORT_PRIVATE QuicConnectionManagerLogger: public QuicConnectionLoggingInterface,
    public MultipathSendAlgorithmInterface::LoggingInterface {
public:
  QuicConnectionManagerLogger(std::string logfile, const QuicClock* clock,
      QuicConnectionResolver* connectionResolver);
  ~QuicConnectionManagerLogger() override;

  void OnPacketSent(QuicConnection* connection, QuicPacketNumber packetNumber,
      QuicPacketLength packetLength) override;

  void OnPacketReceived(QuicConnection* connection, QuicPacketNumber packetNumber,
      QuicPacketLength packetLength) override;

  void OnPacketLost(QuicConnection* connection, QuicPacketNumber packetNumber,
      QuicPacketLength packetLength, TransmissionType transmissionType) override;

  void OnAckSent(QuicConnection* connection, QuicPacketLength ackLength) override;

  void OnAckReceived(QuicConnection* connection, QuicPacketNumber packetNumber,
      QuicPacketLength packetLength, QuicTime::Delta ackDelayTime,
      QuicTime::Delta rtt) override;

  void OnStreamFrameSent(QuicConnection* connection, QuicStreamId streamId,
      QuicByteCount length) override;

  void OnStreamFrameReceived(QuicConnection* connection, QuicStreamId streamId,
      QuicByteCount length) override;

  void OnLoss(const QuicSubflowDescriptor& subflowDescriptor,
      QuicPacketLength packetLength, QuicByteCount newCongestionWindow) override;

  void OnAck(const QuicSubflowDescriptor& subflowDescriptor,
      QuicPacketLength packetLength, QuicByteCount newCongestionWindow,
      bool isInSlowStart) override;

  void OnRttUpdated(const QuicSubflowDescriptor& subflowDescriptor,
          QuicTime::Delta newRtt) override;

  void OnSuccessfulHttpRequest(QuicTime::Delta requestDelta);

private:
  struct Statistic {
    Statistic();
    Statistic(const Statistic& other);
    uint64_t nPacketsSent;
    uint64_t nBytesSent;
    uint64_t nPacketsReceived;
    uint64_t nPacketsLost;
    uint64_t nBytesLost;
    uint64_t nPacketsAcked;
    uint64_t nBytesAcked;
    uint64_t sumAckDelayTime;
    uint64_t sumRtt;
    uint64_t nAcksSent;
    uint64_t nAckBytesSent;
    uint64_t nStreamFramesSent;
    uint64_t nStreamBytesSent;
    uint64_t nStreamFramesReceived;
    uint64_t nStreamBytesReceived;
  };
  void RecordEvent(std::string eventType, QuicSubflowId id, std::string content);
  void LogStatistic(std::string prefix, Statistic s, QuicTime::Delta);
  void LogIntervalStatistic(QuicTime now);
  void LogFullStatistic(QuicTime now);

  const std::string EVENT_PACKET_SENT = "PACKET_SENT";
  const std::string EVENT_PACKET_RECEIVED = "PACKET_RECEIVED";
  const std::string EVENT_PACKET_LOST = "PACKET_LOST";
  const std::string EVENT_ACK_SENT = "ACK_SENT";
  const std::string EVENT_ACK_RECEIVED = "ACK_RECEIVED";
  const std::string EVENT_STREAM_RECEIVED = "STREAM_RECEIVED";
  const std::string EVENT_STREAM_SENT = "STREAM_SENT";
  const std::string EVENT_LOSS_ALGORITHM_ACK = "LOSS_ALGORITHM_ACK";
  const std::string EVENT_LOSS_ALGORITHM_LOSS = "LOSS_ALGORITHM_LOSS";
  const std::string EVENT_LOSS_ALGORITHM_RTT = "LOSS_ALGORITHM_RTT";
  const std::string EVENT_SUCCESSFUL_HTTP_REQUEST = "SUCCESSFUL_HTTP_REQUEST";

  const QuicClock* clock_;

  QuicTime::Delta log_interval_ = QuicTime::Delta::FromSeconds(1);
  QuicTime start_time_;
  QuicTime last_interval_log_;
  std::map<QuicSubflowId, Statistic> interval_statistics_;
  std::map<QuicSubflowId, Statistic> full_statistics_;
  QuicConnectionResolver* connection_resolver_;

  //NetLogWithSource net_log_;

  DISALLOW_COPY_AND_ASSIGN(QuicConnectionManagerLogger);
};

}
// namespace net

#endif  // NET_QUIC_CORE_QUIC_CONNECTION_MANAGER_LOGGER_H_

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

#ifndef NET_QUIC_CORE_CONGESTION_CONTROL_MULTIPATH_SEND_ALGORITHM_INTERFACE_H_
#define NET_QUIC_CORE_CONGESTION_CONTROL_MULTIPATH_SEND_ALGORITHM_INTERFACE_H_

#include <list>

#include "net/quic/platform/api/quic_export.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/core/frames/quic_frame.h"
#include "net/quic/core/congestion_control/multipath_scheduler_interface.h"
#include "net/quic/platform/api/quic_subflow_descriptor.h"
#include "net/quic/core/quic_config.h"
#include "net/quic/core/quic_unacked_packet_map.h"
#include "net/quic/core/congestion_control/hybrid_slow_start.h"
#include "net/quic/core/quic_multipath_configuration.h"
#include "net/quic/core/congestion_control/prr_sender.h"

namespace net {

class CachedNetworkParameters;
struct QuicTransmissionInfo;

class QUIC_EXPORT_PRIVATE MultipathSendAlgorithmInterface {
public:
  // Class that receives callbacks from the send algorithm whenever events happen that should
  // be logged.
  class QUIC_EXPORT_PRIVATE LoggingInterface {
  public:
    virtual ~LoggingInterface() {
    }

    virtual void OnLoss(const QuicSubflowDescriptor& subflowDescriptor,
        QuicPacketLength packetLength, QuicByteCount newCongestionWindow) = 0;
    virtual void OnAck(const QuicSubflowDescriptor& subflowDescriptor,
        QuicPacketLength packetLength, QuicByteCount newCongestionWindow,
        bool isInSlowStart) = 0;
    virtual void OnRttUpdated(const QuicSubflowDescriptor& subflowDescriptor,
        QuicTime::Delta newRtt) = 0;
  };

  // A sorted vector of packets.
  typedef std::vector<std::pair<QuicPacketNumber, QuicPacketLength>> CongestionVector;
  const QuicPacketLength max_frame_length = 1; //TODO(cyrill) get actual max frame length
  const QuicByteCount kMaxBurstBytes = 3 * kDefaultTCPMSS;
  const QuicByteCount kInitialCongestionWindowInBytes = kInitialCongestionWindow
      * kDefaultTCPMSS;
  //const float kRenoBeta = 0.7f;               // Reno backoff factor.
  const float kRateBasedExtraCwnd = 1.5f; // CWND for rate based sending.

  static bool rateBasedSending;
  static bool noPrr;
  static bool slowStartLargeReduction;

  enum SendReason {
    ENCRYPTED_TRANSMISSION, UNENCRYPTED_TRANSMISSION
  };

  MultipathSendAlgorithmInterface(MultipathSchedulerInterface* scheduler);
  virtual ~MultipathSendAlgorithmInterface();

  // Configuration & creation
  virtual void AddSubflow(const QuicSubflowDescriptor& subflowDescriptor,
      RttStats* rttStats, QuicUnackedPacketMap* unackedPacketMap);
  void SetPacketHandlingMethod(
      QuicMultipathConfiguration::PacketScheduling packetSchedulingMethod);
  void setLoggingInterface(LoggingInterface* loggingInterface) {
    logging_interface_ = loggingInterface;
  }
  /*void SetMaxTotalBandwidth(QuicBandwidth bandwidth, QuicSubflowDescriptor independentSubflow) {
    max_total_bandwidth_ = bandwidth;
    max_bandwidth_independent_subflow_ = independentSubflow;
  }

  // Pacing sender testing
  QuicBandwidth GetMaxBandwidth(const QuicSubflowDescriptor& descriptor,
      QuicByteCount bytes_in_flight) {
    if(max_total_bandwidth_.IsZero()) {
      QUIC_LOG(WARNING) << descriptor.ToString() << " max bandwidth = 0";
      return QuicBandwidth::Infinite();
    }
    if(descriptor == max_bandwidth_independent_subflow_) {
      QUIC_LOG(WARNING) << descriptor.ToString() << " is independent subflow => max bandwidth = inf";
      return QuicBandwidth::Infinite();
    } else {
      QuicBandwidth minReducedBandwidth = QuicBandwidth::FromKBitsPerSecond(500);
      QuicBandwidth independentFlowBandwidth = PacingRate(max_bandwidth_independent_subflow_, bytes_in_flight);
      if(independentFlowBandwidth > max_total_bandwidth_ ||
          max_total_bandwidth_ - independentFlowBandwidth < minReducedBandwidth) {
        QUIC_LOG(WARNING) << descriptor.ToString() <<
            "independent flow bandwith (" << independentFlowBandwidth <<
            ") > max bandwidth(" << max_total_bandwidth_ <<
            ") || max bandwidth - independent bandwidth < min bandwidth(" <<
            minReducedBandwidth << ")";
        return minReducedBandwidth;
      } else {
        QUIC_LOG(WARNING) << descriptor.ToString() <<
            " max bandwidth = " << (max_total_bandwidth_ - independentFlowBandwidth).ToKBitsPerSecond();
        return max_total_bandwidth_ - independentFlowBandwidth;
      }
    }
  }*/

  // SS & CA increase & decrease.
  virtual void OnLoss(const QuicSubflowDescriptor& descriptor,
      QuicPacketLength bytes_lost) = 0;
  virtual void OnAck(const QuicSubflowDescriptor& descriptor,
      QuicPacketLength bytes_acked) = 0;
  virtual QuicByteCount CongestionWindowAfterPacketLoss(
      const QuicSubflowDescriptor& descriptor) = 0;
  virtual QuicByteCount CongestionWindowAfterPacketAck(
      const QuicSubflowDescriptor& descriptor, QuicByteCount prior_in_flight,
      QuicPacketLength length) = 0;

  virtual void SetFromConfig(const QuicConfig& config, Perspective perspective);

  // Sets the number of connections to emulate when doing congestion control,
  // particularly for congestion avoidance.  Can be set any time.
  virtual void SetNumEmulatedConnections(int num_connections);

  // Indicates an update to the congestion state, caused either by an incoming
  // ack or loss event timeout.  |rtt_updated| indicates whether a new
  // latest_rtt sample has been taken, |prior_in_flight| the bytes in flight
  // prior to the congestion event.  |acked_packets| and |lost_packets| are any
  // packets considered acked or lost as a result of the congestion event.
  virtual void OnCongestionEvent(const QuicSubflowDescriptor& descriptor,
      bool rtt_updated, QuicByteCount prior_in_flight, QuicTime event_time,
      const CongestionVector& acked_packets,
      const CongestionVector& lost_packets);

  // Inform that we sent |bytes| to the wire, and if the packet is
  // retransmittable. Returns true if the packet should be tracked by the
  // congestion manager and included in bytes_in_flight, false otherwise.
  // |bytes_in_flight| is the number of bytes in flight before the packet was
  // sent.
  // Note: this function must be called for every packet sent to the wire.
  virtual bool OnPacketSent(const QuicSubflowDescriptor& descriptor,
      QuicTime sent_time, QuicByteCount bytes_in_flight,
      QuicPacketNumber packet_number, QuicByteCount bytes,
      HasRetransmittableData is_retransmittable);

  // Called when the retransmission timeout fires.  Neither OnPacketAbandoned
  // nor OnPacketLost will be called for these packets.
  virtual void OnRetransmissionTimeout(const QuicSubflowDescriptor& descriptor,
      bool packets_retransmitted);

  // Called when connection migrates and cwnd needs to be reset.
  // Not used in multipath quic.
  virtual void OnConnectionMigration();

  // Calculate the time until we can send the next packet.
  virtual QuicTime::Delta TimeUntilSend(const QuicSubflowDescriptor& descriptor,
      QuicTime now, QuicByteCount bytes_in_flight);

  // The pacing rate of the send algorithm.  May be zero if the rate is unknown.
  virtual QuicBandwidth PacingRate(const QuicSubflowDescriptor& descriptor,
      QuicByteCount bytes_in_flight) const;

  // What's the current estimated bandwidth in bytes per second.
  // Returns 0 when it does not have an estimate.
  virtual QuicBandwidth BandwidthEstimate(
      const QuicSubflowDescriptor& descriptor) const;

  // Returns the size of the current total congestion window in bytes.  Note, this is
  // not the *available* window.  Some send algorithms may not use a congestion
  // window and will return 0.
  virtual QuicByteCount GetCongestionWindow(
      const QuicSubflowDescriptor& descriptor) const;

  // Whether the send algorithm is currently in slow start.  When true, the
  // BandwidthEstimate is expected to be too low.
  virtual bool InSlowStart(const QuicSubflowDescriptor& descriptor) const;

  // Whether the send algorithm is currently in recovery.
  virtual bool InRecovery(const QuicSubflowDescriptor& descriptor) const;

  // Returns the size of the slow start congestion window in bytes,
  // aka ssthresh.  Some send algorithms do not define a slow start
  // threshold and will return 0.
  virtual QuicByteCount GetSlowStartThreshold(
      const QuicSubflowDescriptor& descriptor) const;

  virtual CongestionControlType GetCongestionControlType() const;

  // Called by the Session when we get a bandwidth estimate from the client.
  // Uses the max bandwidth in the params if |max_bandwidth_resumption| is true.
  virtual void ResumeConnectionState(
      const CachedNetworkParameters& cached_network_params,
      bool max_bandwidth_resumption);

  // Retrieves debugging information about the current state of the
  // send algorithm.
  virtual std::string GetDebugState() const;

  // Called when the connection has no outstanding data to send. Specifically,
  // this means that none of the data streams are write-blocked, there are no
  // packets in the connection queue, and there are no pending retransmissins,
  // i.e. the sender cannot send anything for reasons other than being blocked
  // by congestion controller. This includes cases when the connection is
  // blocked by the flow controller.
  //
  // The fact that this method is called does not necessarily imply that the
  // connection would not be blocked by the congestion control if it actually
  // tried to send data. If the congestion control algorithm needs to exclude
  // such cases, it should use the internal state it uses for congestion control
  // for that.
  virtual void OnApplicationLimited(QuicByteCount bytes_in_flight);

  // Multipath scheduling

  // The following functions return the descriptor of the subflow where a frame should
  // be sent on. If hint.IsInitialized() returns true it describes the subflow on which
  // we received the stream frame (used for returning crypto handshakes on the same subflow).
  // reason is used to determine if the frame is a crypto handshake message.
  // After the frame was sent, SentOnSubflow() should be called.
  // For GetNextRetransmissionSubflow(), after scheduling the retransmission, SentOnSubflow()
  // should be called.
  virtual QuicSubflowDescriptor GetNextStreamFrameSubflow(QuicStreamId streamId,
      size_t length, const QuicSubflowDescriptor& hint, SendReason reason);
  // If hint.IsInitialized() returns true it describes the subflow which initiated sending
  // the frame.
  virtual QuicSubflowDescriptor GetNextControlFrameSubflow(
      const QuicFrame& frame, const QuicSubflowDescriptor& hint);
  // Choose the subflow on which this packet should be retransmitted.
  virtual QuicSubflowDescriptor GetNextRetransmissionSubflow(
      const QuicTransmissionInfo& transmission_info,
      const QuicSubflowDescriptor& hint);
  virtual void SentOnSubflow(const QuicSubflowDescriptor& descriptor,
      QuicPacketLength length);

  // Returns the additional subflows for which we should send ack frames on the subflow described by
  // packetSubflowDescriptor.
  virtual std::list<QuicSubflowDescriptor> AppendAckFrames(
      const QuicSubflowDescriptor& packetSubflowDescriptor);
  // Is called after AppendAckFrames() by the connection manager to inform the send algorithm
  // which ack frames were sent.
  virtual void AckFramesAppended(
      const std::list<QuicSubflowDescriptor>& ackFrameSubflowDescriptors);

  // Notification if an ack frame of a subflow was updated. Used for adding the last
  // modified ack first.
  virtual void OnAckFrameUpdated(
      const QuicSubflowDescriptor& subflowDescriptor);

  void InitialEncryptionEstablished(const QuicSubflowDescriptor& descriptor);
  virtual void ForwardSecureEncryptionEstablished(
      const QuicSubflowDescriptor& descriptor);
  EncryptionLevel GetEncryptionLevel(const QuicSubflowDescriptor& descriptor);

  // debugging purposes
  void Log(const QuicSubflowDescriptor& descriptor, std::string s, bool forceLogging = false);

protected:
  QuicSubflowDescriptor uninitialized_subflow_descriptor_;

  // Congestion control
  QuicByteCount GetMinimumCongestionWindow() const;
  QuicByteCount GetMinimumSlowStartThreshold() const;
  bool IsCwndLimited(const QuicSubflowDescriptor& descriptor,
      QuicByteCount bytes_in_flight) const;
  QuicByteCount ssthresh(const QuicSubflowDescriptor& descriptor) const;
  QuicByteCount cwnd(const QuicSubflowDescriptor& descriptor) const;
  QuicTime::Delta srtt(const QuicSubflowDescriptor& descriptor) const;
  QuicTime::Delta MinRtt(const QuicSubflowDescriptor& descriptor) const;
  QuicTime::Delta LatestRtt(const QuicSubflowDescriptor& descriptor) const;
  QuicTime::Delta InitialRtt(const QuicSubflowDescriptor& descriptor) const;
  HybridSlowStart GetHybridSlowStart(const QuicSubflowDescriptor& descriptor);
  PrrSender Prr(const QuicSubflowDescriptor& descriptor);
  QuicPacketNumber LargestSentPacketNumber(
      const QuicSubflowDescriptor& descriptor) const;
  void SetLargestSentPacketNumber(const QuicSubflowDescriptor& descriptor,
      QuicPacketNumber packetNumber);
  QuicPacketNumber LargestAckedPacketNumber(
      const QuicSubflowDescriptor& descriptor) const;
  void SetLargestAckedPacketNumber(const QuicSubflowDescriptor& descriptor,
      QuicPacketNumber packetNumber);
  QuicPacketNumber LargestSentAtLastCutback(
      const QuicSubflowDescriptor& descriptor) const;
  void SetLargestSentAtLastCutback(const QuicSubflowDescriptor& descriptor,
      QuicPacketNumber packetNumber);
  bool LastCutbackExitedSlowstart(
      const QuicSubflowDescriptor& descriptor) const;
  void SetLastCutbackExitedSlowstart(const QuicSubflowDescriptor& descriptor,
      bool val);
  QuicByteCount MinSlowStartExitWindow(
      const QuicSubflowDescriptor& descriptor) const;
  void SetMinSlowStartExitWindow(const QuicSubflowDescriptor& descriptor,
      QuicByteCount window);

  // Multipath scheduling
  virtual bool FitsCongestionWindow(const QuicSubflowDescriptor& descriptor,
      QuicPacketLength length);
  virtual bool HasForwardSecureSubflow();
  virtual bool IsForwardSecure(const QuicSubflowDescriptor& descriptor);
  virtual bool IsInitialSecure(const QuicSubflowDescriptor& descriptor);
  virtual bool GetNumberOfSubflows() const;
  // Returns the next subflow provided by the scheduler which has enough space in its
  // congestion window to send a packet of size |length|. If there is no such subflow,
  // it returns the next subflow with sufficient encryption even if there is not enough
  // space in the congestion window.
  //
  // If |allowInitialEncryption| is false, we only allow subflows with forward secure encryption.
  // If it is true, we allow subflows with initial or forward secure encryption.
  QuicSubflowDescriptor GetNextSubflow(QuicPacketLength length,
      bool allowInitialEncryption);
  virtual QuicSubflowDescriptor GetNextForwardSecureSubflow();
  void ExitSlowstart(const QuicSubflowDescriptor& descriptor);

  enum SubflowCongestionState {
    SUBFLOW_CONGESTION_SLOWSTART, SUBFLOW_CONGESTION_RECOVERY
  };

  struct SubflowParameters {
    SubflowParameters();
    SubflowParameters(RttStats* rttStats,
        QuicUnackedPacketMap* unackedPacketMap,
        QuicByteCount initialCongestionWindow);
    SubflowParameters(const SubflowParameters& other);
    RttStats* rtt_stats;
    QuicUnackedPacketMap* unacked_packet_map;
    QuicByteCount congestion_window;
    SubflowCongestionState congestion_state;
    bool forward_secure_encryption_established;
    EncryptionLevel encryption_level;
    bool in_slow_start;
    QuicByteCount ssthresh;
    HybridSlowStart hybrid_slow_start;
    PrrSender prr;
    // Track the largest packet that has been sent.
    QuicPacketNumber largest_sent_packet_number;

    // Track the largest packet that has been acked.
    QuicPacketNumber largest_acked_packet_number;

    // Track the largest packet number outstanding when a CWND cutback occurs.
    QuicPacketNumber largest_sent_at_last_cutback;

    // Whether the last loss event caused us to exit slowstart.
    // Used for stats collection of slowstart_packets_lost
    bool last_cutback_exited_slowstart;

    // The minimum window when exiting slow start with large reduction.
    QuicByteCount min_slow_start_exit_window;
  };

  std::map<QuicSubflowDescriptor, SubflowParameters> parameters_;

  bool TracksDescriptor(const QuicSubflowDescriptor& descriptor) const {
    return parameters_.find(descriptor) != parameters_.end();
  }
  const SubflowParameters& GetParameters(
      const QuicSubflowDescriptor& descriptor) const {
    DCHECK(TracksDescriptor(descriptor));
    return parameters_.at(descriptor);
  }
  SubflowParameters& GetMutableParameters(
      const QuicSubflowDescriptor& descriptor) {
    DCHECK(TracksDescriptor(descriptor));
    return parameters_[descriptor];
  }

  MultipathSchedulerInterface* GetScheduler() {
    return scheduler_.get();
  }

  // When true, use rate based sending instead of only sending if there's CWND.
  bool rate_based_sending_;

  // When true, use unity pacing instead of PRR.
  bool no_prr_;

  // When true, exit slow start with large cutback of congestion window.
  bool slow_start_large_reduction_;

  LoggingInterface* logging_interface_;

private:
  std::unique_ptr<MultipathSchedulerInterface> scheduler_;

  // Used for testing only
  QuicBandwidth max_total_bandwidth_;
  QuicSubflowDescriptor max_bandwidth_independent_subflow_;

  void setCwnd(const QuicSubflowDescriptor& descriptor, QuicByteCount newCwnd);
  void setSsthresh(const QuicSubflowDescriptor& descriptor,
      QuicByteCount newSsthresh);
  void Ack(const QuicSubflowDescriptor& descriptor,
      QuicPacketNumber packet_number, QuicByteCount bytes_acked,
      QuicByteCount prior_in_flight);
  void Loss(const QuicSubflowDescriptor& descriptor,
      QuicPacketNumber packet_number, QuicByteCount bytes_lost,
      QuicByteCount prior_in_flight);

  DISALLOW_COPY_AND_ASSIGN(MultipathSendAlgorithmInterface);
};

} // namespace net

#endif  // NET_QUIC_CORE_CONGESTION_CONTROL_MULTIPATH_SEND_ALGORITHM_INTERFACE_H_

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/multipath_scheduler_algorithm.h"

namespace net {

MultipathSchedulerAlgorithm::MultipathSchedulerAlgorithm(
    QuicMultipathConfiguration::PacketScheduling packetSchedulingMethod)
    : subflow_descriptors_with_rtt_(std::vector<SubflowWithRtt>()), ack_frame_descriptors_(
        std::vector<QuicSubflowDescriptor>()), current_index_(0), packet_scheduling_(
        packetSchedulingMethod) {

}

MultipathSchedulerAlgorithm::~MultipathSchedulerAlgorithm() {

}

void MultipathSchedulerAlgorithm::AddSubflow(
    const QuicSubflowDescriptor& subflowDescriptor, const RttStats* rttStats) {
  for (SubflowWithRtt s : subflow_descriptors_with_rtt_) {
    if (s.GetSubflowDescriptor() == subflowDescriptor) {
      DCHECK(false);
    }
  }
  MultipathSchedulerInterface::AddSubflow(subflowDescriptor, rttStats);
  subflow_descriptors_with_rtt_.push_back(
      SubflowWithRtt(rttStats, subflowDescriptor));
}

std::list<QuicSubflowDescriptor> MultipathSchedulerAlgorithm::GetSubflowPriority() {
  std::vector<SubflowWithRtt> p;
  if (packet_scheduling_ == QuicMultipathConfiguration::PacketScheduling::SMALLEST_RTT_FIRST) {
    p.insert(p.end(), subflow_descriptors_with_rtt_.begin(),
        subflow_descriptors_with_rtt_.end());
    std::sort(p.begin(), p.end(),
        [](const SubflowWithRtt& a, const SubflowWithRtt& b) {return a.GetSmoothedRtt() < b.GetSmoothedRtt();});
  } else { // round robin
    size_t index = current_index_;
    p.insert(p.end(), subflow_descriptors_with_rtt_.begin() + index,
        subflow_descriptors_with_rtt_.end());
    p.insert(p.end(), subflow_descriptors_with_rtt_.begin(),
        subflow_descriptors_with_rtt_.begin() + index);
  }
  std::list<QuicSubflowDescriptor> pOut;
  std::transform(p.begin(), p.end(), std::back_inserter(pOut), [](const SubflowWithRtt& a) { return a.GetSubflowDescriptor(); });

  std::string s;
  for(const QuicSubflowDescriptor& d: pOut) {
    s += (s==""?"":",") + d.ToString();
  }
  QUIC_LOG(INFO) << "subflow priority = " << s;

  return pOut;
}
void MultipathSchedulerAlgorithm::UsedSubflow(
    const QuicSubflowDescriptor& descriptor) {
  if (packet_scheduling_ == QuicMultipathConfiguration::PacketScheduling::ROUNDROBIN) {
    // Change current index to the next index.
    size_t index = 1;
    for (SubflowWithRtt d : subflow_descriptors_with_rtt_) {
      if (d.GetSubflowDescriptor() == descriptor) {
        current_index_ = index;
      }
      ++index;
    }
  }
}

std::list<QuicSubflowDescriptor> MultipathSchedulerAlgorithm::GetAckFramePriority(
    const QuicSubflowDescriptor& packetSubflowDescriptor) {
  return std::list<QuicSubflowDescriptor>(ack_frame_descriptors_.begin(),
      ack_frame_descriptors_.end());
}
void MultipathSchedulerAlgorithm::AckFramesAppended(
    std::list<QuicSubflowDescriptor> descriptors) {
  for (auto it : descriptors) {
    auto pos = std::find(ack_frame_descriptors_.begin(),
        ack_frame_descriptors_.end(), it);
    if (pos != ack_frame_descriptors_.end()) {
      ack_frame_descriptors_.erase(pos);
    }
  }
}
void MultipathSchedulerAlgorithm::OnAckFrameUpdated(
    const QuicSubflowDescriptor& descriptor) {
  ack_frame_descriptors_.push_back(descriptor);
}

void MultipathSchedulerAlgorithm::SetPacketSchedulingMethod(
    QuicMultipathConfiguration::PacketScheduling packetScheduling) {
  packet_scheduling_ = packetScheduling;
}

size_t MultipathSchedulerAlgorithm::AdvanceIndex() {
  return (current_index_++) % subflow_descriptors_with_rtt_.size();
}
void MultipathSchedulerAlgorithm::SetIndex(size_t index) {
  current_index_ = index;
}

MultipathSchedulerAlgorithm::SubflowWithRtt::SubflowWithRtt(
    const RttStats* rttStats, const QuicSubflowDescriptor& subflowDescriptor)
    : rtt_stats_(rttStats), subflow_descriptor_(subflowDescriptor) {

}

QuicTime::Delta MultipathSchedulerAlgorithm::SubflowWithRtt::GetSmoothedRtt() const {
  return rtt_stats_->smoothed_rtt();
}

const QuicSubflowDescriptor& MultipathSchedulerAlgorithm::SubflowWithRtt::GetSubflowDescriptor() const {
  return subflow_descriptor_;
}

}

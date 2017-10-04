// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_PENDING_RETRANSMISSION_H_
#define NET_QUIC_CORE_QUIC_PENDING_RETRANSMISSION_H_

#include "net/quic/core/frames/quic_frame.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_export.h"
#include "net/quic/core/quic_packet_descriptor.h"

namespace net {

// Struct to store the pending retransmission information.
struct QUIC_EXPORT_PRIVATE QuicPendingRetransmission {
  QuicPendingRetransmission(QuicPacketDescriptor packet_descriptor,
                            TransmissionType transmission_type,
                            const QuicFrames& retransmittable_frames,
                            bool has_crypto_handshake,
                            int num_padding_bytes,
                            EncryptionLevel encryption_level,
                            QuicPacketNumberLength packet_number_length)
      : packet_descriptor(packet_descriptor),
        retransmittable_frames(retransmittable_frames),
        transmission_type(transmission_type),
        has_crypto_handshake(has_crypto_handshake),
        num_padding_bytes(num_padding_bytes),
        encryption_level(encryption_level),
        packet_number_length(packet_number_length) {}

  QuicPacketDescriptor packet_descriptor;
  const QuicFrames& retransmittable_frames;
  TransmissionType transmission_type;
  bool has_crypto_handshake;
  int num_padding_bytes;
  EncryptionLevel encryption_level;
  QuicPacketNumberLength packet_number_length;
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_PENDING_RETRANSMISSION_H_

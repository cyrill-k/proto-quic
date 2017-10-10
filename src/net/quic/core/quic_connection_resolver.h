// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_CONNECTION_RESOLVER_H_
#define NET_QUIC_CORE_QUIC_CONNECTION_RESOLVER_H_

#include "base/macros.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_subflow_descriptor.h"

namespace net {

class QUIC_EXPORT_PRIVATE QuicConnectionResolver {
public:
  virtual ~QuicConnectionResolver() {}

  virtual QuicSubflowId GetSubflowId(const QuicSubflowDescriptor& subflowDescriptor) = 0;
};

}
// namespace net

#endif  // NET_QUIC_CORE_QUIC_CONNECTION_RESOLVER_H_

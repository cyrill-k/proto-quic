// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A binary wrapper for QuicServer.  It listens forever on --port
// (default 6121) until it's killed or ctrl-cd to death.

#include <iostream>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "net/quic/chromium/crypto/proof_source_chromium.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/tools/quic/quic_http_response_cache.h"
#include "net/tools/quic/quic_multipath_server.h"
#include "net/quic/core/quic_multipath_configuration.h"

using net::QuicMultipathConfiguration;

// The port the quic server will listen on.
int32_t FLAGS_port = 6121;

std::unique_ptr<net::ProofSource> CreateProofSource(
    const base::FilePath& cert_path, const base::FilePath& key_path) {
  std::unique_ptr<net::ProofSourceChromium> proof_source(
      new net::ProofSourceChromium());
  CHECK(proof_source->Initialize(cert_path, key_path, base::FilePath()));
  return std::move(proof_source);
}

int main(int argc, char* argv[]) {
  base::AtExitManager exit_manager;
  base::MessageLoopForIO message_loop;

  base::CommandLine::Init(argc, argv);
  base::CommandLine* line = base::CommandLine::ForCurrentProcess();

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  CHECK(logging::InitLogging(settings));

  if (line->HasSwitch("h") || line->HasSwitch("help")) {
    const char* help_str = "Usage: quic_server [options]\n"
        "\n"
        "Options:\n"
        "-h, --help                  show this help message and exit\n"
        "--port=<port>               specify the port to listen on\n"
        "--quic_response_cache_dir  directory containing response data\n"
        "                            to load\n"
        "--certificate_file=<file>   path to the certificate chain\n"
        "--key_file=<file>           path to the pkcs8 private key\n"
        "--ack                       Ack handling method: simple, roundrobin or smallestrtt\n"
        "--pkt                       Packet scheduling method: roundrobin or smallestrtt\n";
    std::cout << help_str;
    exit(0);
  }

  net::QuicHttpResponseCache response_cache;
  if (line->HasSwitch("quic_response_cache_dir")) {
    response_cache.InitializeFromDirectory(
        line->GetSwitchValueASCII("quic_response_cache_dir"));
  }

  if (line->HasSwitch("port")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("port"), &FLAGS_port)) {
      LOG(ERROR) << "--port must be an integer\n";
      return 1;
    }
  }

  if (!line->HasSwitch("certificate_file")) {
    LOG(ERROR) << "missing --certificate_file";
    return 1;
  }

  if (!line->HasSwitch("key_file")) {
    LOG(ERROR) << "missing --key_file";
    return 1;
  }

  net::QuicIpAddress address = net::QuicIpAddress::Any6();
  if (line->HasSwitch("host")) {
    address.FromString(line->GetSwitchValueASCII("host"));
    LOG(INFO) << "using host: " << address.ToString();
  }

  QuicMultipathConfiguration::AckSending ackHandlingMethod =
      QuicMultipathConfiguration::DEFAULT_ACK_HANDLING;
  if (line->HasSwitch("ack")) {
    if (line->GetSwitchValueASCII("ack") == "simple") {
      ackHandlingMethod = QuicMultipathConfiguration::AckSending::SIMPLE;
    } else if (line->GetSwitchValueASCII("ack") == "roundrobin") {
      ackHandlingMethod = QuicMultipathConfiguration::AckSending::ROUNDROBIN;
    } else if (line->GetSwitchValueASCII("ack") == "smallestrtt") {
      ackHandlingMethod =
          QuicMultipathConfiguration::AckSending::SEND_ON_SMALLEST_RTT;
    }
  }

  QuicMultipathConfiguration::PacketScheduling packetSchedulingMethod =
      QuicMultipathConfiguration::DEFAULT_PACKET_SCHEDULING;
  if (line->HasSwitch("pkt")) {
    if (line->GetSwitchValueASCII("pkt") == "roundrobin") {
      packetSchedulingMethod =
          QuicMultipathConfiguration::PacketScheduling::ROUNDROBIN;
    } else if (line->GetSwitchValueASCII("pkt") == "smallestrtt") {
      packetSchedulingMethod =
          QuicMultipathConfiguration::PacketScheduling::SMALLEST_RTT_FIRST;
    }
  }

  QuicMultipathConfiguration mpConf =
      QuicMultipathConfiguration::CreateServerConfiguration(
          packetSchedulingMethod, ackHandlingMethod);
  net::QuicConfig config;
  net::QuicMultipathServer server(
      CreateProofSource(line->GetSwitchValuePath("certificate_file"),
          line->GetSwitchValuePath("key_file")), config,
      net::QuicCryptoServerConfig::ConfigOptions(), net::AllSupportedVersions(),
      &response_cache, mpConf);

  int rc = server.CreateUDPSocketAndListen(
      net::QuicSocketAddress(address, FLAGS_port));
  //int rc = server.CreateUDPSocketAndListen(
  //    net::QuicSocketAddress(net::QuicIpAddress::Any6(), FLAGS_port));
  if (rc < 0) {
    return 1;
  }

  while (1) {
    server.WaitForEvents();
  }
}

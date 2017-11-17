// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicClient.
// Connects to a host using QUIC, sends a request to the provided URL, and
// displays the response.
//
// Some usage examples:
//
//   TODO(rtenneti): make --host optional by getting IP Address of URL's host.
//
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//
// Standard request/response:
//   quic_client http://www.google.com  --host=${IP}
//   quic_client http://www.google.com --quiet  --host=${IP}
//   quic_client https://www.google.com --port=443  --host=${IP}
//
// Use a specific version:
//   quic_client http://www.google.com --quic_version=23  --host=${IP}
//
// Send a POST instead of a GET:
//   quic_client http://www.google.com --body="this is a POST body" --host=${IP}
//
// Append additional headers to the request:
//   quic_client http://www.google.com  --host=${IP}
//               --headers="Header-A: 1234; Header-B: 5678"
//
// Connect to a host different to the URL being requested:
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//   quic_client mail.google.com --host=${IP}
//
// Try to connect to a host which does not speak QUIC:
//   Get IP address of the www.example.com
//   IP=`dig www.example.com +short | head -1`
//   quic_client http://www.example.com --host=${IP}

#include <iostream>
#include <string>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/message_loop/message_loop.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_known_logs.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/transport_security_state.h"
#include "net/quic/chromium/crypto/proof_verifier_chromium.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/platform/api/quic_str_cat.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/quic/platform/api/quic_text_utils.h"
#include "net/quic/platform/api/quic_url.h"
#include "net/spdy/core/spdy_header_block.h"
#include "net/tools/epoll_server/epoll_server.h"
#include "net/tools/quic/quic_client.h"
#include "net/tools/quic/synchronous_host_resolver.h"
#include "net/tools/quic/quic_multipath_client.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/core/quic_connection_manager.h"
#include "net/quic/core/congestion_control/multipath_scheduler_algorithm.h"
#include "net/quic/core/quic_multipath_configuration.h"
#include "net/quic/platform/api/quic_clock.h"
#include "net/quic/core/quic_time.h"
#include "net/quic/core/congestion_control/multipath_send_algorithm_interface.h"
#include "net/quic/core/congestion_control/olia_send_algorithm.h"
#include "net/quic/core/quic_bandwidth.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_connection_manager_logger.h"

using net::CertVerifier;
using net::CTPolicyEnforcer;
using net::CTVerifier;
using net::MultiLogCTVerifier;
using net::ProofVerifier;
using net::ProofVerifierChromium;
using net::QuicStringPiece;
using net::QuicTextUtils;
using net::QuicUrl;
using net::SpdyHeaderBlock;
using net::TransportSecurityState;
using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::cin;
using net::QuicSubflowId;
using net::QuicConnectionManager;
using net::MultipathSchedulerAlgorithm;
using net::QuicMultipathConfiguration;
using net::QuicClock;
using net::QuicTime;
using net::MultipathSendAlgorithmInterface;
using net::OliaSendAlgorithm;
using net::QuicBandwidth;
using net::QuicConnection;
using net::QuicConnectionManagerLogger;

// The IP or hostname the quic client will connect to.
string FLAGS_host = "";
// The port to connect to.
int32_t FLAGS_port = 0;
// If set, send a POST with this body.
string FLAGS_body = "";
// If set, contents are converted from hex to ascii, before sending as body of
// a POST. e.g. --body_hex=\"68656c6c6f\"
string FLAGS_body_hex = "";
// A semicolon separated list of key:value pairs to add to request headers.
string FLAGS_headers = "";
// Set to true for a quieter output experience.
bool FLAGS_quiet = false;
// QUIC version to speak, e.g. 21. If not set, then all available versions are
// offered in the handshake.
int32_t FLAGS_quic_version = -1;
// If true, a version mismatch in the handshake is not considered a failure.
// Useful for probing a server to determine if it speaks any version of QUIC.
bool FLAGS_version_mismatch_ok = false;
// If true, an HTTP response code of 3xx is considered to be a successful
// response, otherwise a failure.
bool FLAGS_redirect_is_success = true;
// Initial MTU of the connection.
int32_t FLAGS_initial_mtu = 0;

class FakeProofVerifier: public ProofVerifier {
public:
  net::QuicAsyncStatus VerifyProof(const string& /*hostname*/,
      const uint16_t /*port*/, const string& /*server_config*/,
      net::QuicVersion /*quic_version*/, QuicStringPiece /*chlo_hash*/,
      const std::vector<string>& /*certs*/, const string& /*cert_sct*/,
      const string& /*signature*/, const net::ProofVerifyContext* /*context*/,
      string* /*error_details*/,
      std::unique_ptr<net::ProofVerifyDetails>* /*details*/,
      std::unique_ptr<net::ProofVerifierCallback> /*callback*/) override {
    return net::QUIC_SUCCESS;
  }

  net::QuicAsyncStatus VerifyCertChain(const std::string& /*hostname*/,
      const std::vector<std::string>& /*certs*/,
      const net::ProofVerifyContext* /*verify_context*/,
      std::string* /*error_details*/,
      std::unique_ptr<net::ProofVerifyDetails>* /*verify_details*/,
      std::unique_ptr<net::ProofVerifierCallback> /*callback*/) override {
    return net::QUIC_SUCCESS;
  }
};

void RequestSite(net::QuicMultipathClient& client,
    SpdyHeaderBlock& header_block, string body, const QuicClock* clock) {
  QuicTime start = clock->Now();
  client.SendRequestAndWaitForResponse(header_block, body, true);
  QuicTime end = clock->Now();
  client.session()->connection_manager()->LogSuccessfulHttpRequest(end - start);

  if (!FLAGS_quiet) {
    cout << "Request:" << endl;
    cout << "headers:" << header_block.DebugString();
    if (!FLAGS_body_hex.empty()) {
      cout << "body:\n"
          << QuicTextUtils::HexDump(QuicTextUtils::HexDecode(FLAGS_body_hex))
          << endl;
    } else {
      cout << "body: " << body << endl;
    }
    cout << endl;
    if (!client.preliminary_response_headers().empty()) {
      cout << "Preliminary response headers: "
          << client.preliminary_response_headers() << endl;
      cout << endl;
    }
    cout << "Response:" << endl;
    cout << "headers: " << client.latest_response_headers() << endl;
    string response_body = client.latest_response_body();
    if (!FLAGS_body_hex.empty()) {
      cout << "body(" << response_body.size() << "):\n"
          << (response_body.size() > 2000 ?
              "" : QuicTextUtils::HexDump(response_body)) << endl;
    } else {
      cout << "body(" << response_body.size() << "): "
          << (response_body.size() > 2000 ? "" : response_body) << endl;
    }
    cout << "trailers: " << client.latest_response_trailers() << endl;
  }
}

int Response(net::QuicMultipathClient& client) {
  size_t response_code = client.latest_response_code();
  if (response_code >= 200 && response_code < 300) {
    cout << "Request succeeded (" << response_code << ")." << endl;
    return 0;
  } else if (response_code >= 300 && response_code < 400) {
    if (FLAGS_redirect_is_success) {
      cout << "Request succeeded (redirect " << response_code << ")." << endl;
      return 0;
    } else {
      cout << "Request failed (redirect " << response_code << ")." << endl;
      return 1;
    }
  } else {
    cerr << "Request failed (" << response_code << ")." << endl;
    return 1;
  }
}

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* line = base::CommandLine::ForCurrentProcess();
  const base::CommandLine::StringVector& urls = line->GetArgs();

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  CHECK(logging::InitLogging(settings));

  if (line->HasSwitch("h") || line->HasSwitch("help") || urls.empty()) {
    const char* help_str =
        "Usage: quic_client [options] <url>\n"
            "\n"
            "<url> with scheme must be provided (e.g. http://www.google.com)\n\n"
            "Options:\n"
            "-h, --help                  show this help message and exit\n"
            "--host=<host>               specify the IP address of the hostname to "
            "connect to\n"
            "--port=<port>               specify the port to connect to\n"
            "--body=<body>               specify the body to post\n"
            "--body_hex=<body_hex>       specify the body_hex to be printed out\n"
            "--headers=<headers>         specify a semicolon separated list of "
            "key:value pairs to add to request headers\n"
            "--quiet                     specify for a quieter output experience\n"
            "--quic-version=<quic version> specify QUIC version to speak\n"
            "--version_mismatch_ok       if specified a version mismatch in the "
            "handshake is not considered a failure\n"
            "--redirect_is_success       if specified an HTTP response code of 3xx "
            "is considered to be a successful response, otherwise a failure\n"
            "--initial_mtu=<initial_mtu> specify the initial MTU of the connection"
            "\n"
            "--disable-certificate-verification do not verify certificates\n"
            "--ack                       Ack handling method: simple, roundrobin or smallestrtt\n"
            "--pkt                       Packet scheduling method: roundrobin or smallestrtt\n"
            "--client-ports              List of client ports used: port0,port1,...\n"
            "--client-ip                 Specifiy the client ip\n"
            "--repetitions               The number of identical sequential http requests.\n"
            "--subflows                  The number of subflows that should be created. At least 1.\n"
            "--disable-pacing            Disables pacing\n"
            "--logging-type              simple, extensive, full\n";
    cout << help_str;
    exit(0);
  }
  if (line->HasSwitch("host")) {
    FLAGS_host = line->GetSwitchValueASCII("host");
  }
  if (line->HasSwitch("port")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("port"), &FLAGS_port)) {
      std::cerr << "--port must be an integer\n";
      return 1;
    }
  }
  if (line->HasSwitch("body")) {
    FLAGS_body = line->GetSwitchValueASCII("body");
  }
  if (line->HasSwitch("body_hex")) {
    FLAGS_body_hex = line->GetSwitchValueASCII("body_hex");
  }
  if (line->HasSwitch("headers")) {
    FLAGS_headers = line->GetSwitchValueASCII("headers");
  }
  if (line->HasSwitch("quiet")) {
    FLAGS_quiet = true;
  }
  if (line->HasSwitch("quic-version")) {
    int quic_version;
    if (base::StringToInt(line->GetSwitchValueASCII("quic-version"),
        &quic_version)) {
      FLAGS_quic_version = quic_version;
    }
  }
  if (line->HasSwitch("version_mismatch_ok")) {
    FLAGS_version_mismatch_ok = true;
  }
  if (line->HasSwitch("redirect_is_success")) {
    FLAGS_redirect_is_success = true;
  }
  if (line->HasSwitch("initial_mtu")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("initial_mtu"),
        &FLAGS_initial_mtu)) {
      std::cerr << "--initial_mtu must be an integer\n";
      return 1;
    }
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
  std::vector<unsigned int> clientPorts;
  if (line->HasSwitch("client-ports")) {
    std::stringstream commaPortList(line->GetSwitchValueASCII("client-ports"));
    std::string segment;
    while (std::getline(commaPortList, segment, ',')) {
      unsigned int port = std::atoi(segment.c_str());
      clientPorts.push_back(port);
    }
  }
  net::QuicIpAddress clientIpAddress;
  if (line->HasSwitch("client-ip")) {
    if (!clientIpAddress.FromString(line->GetSwitchValueASCII("client-ip"))) {
      std::cerr << "Invalid client-ip field";
      return 1;
    }
  }
  int nRepetitions = 1;
  if (line->HasSwitch("repetitions")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("repetitions"), &nRepetitions)) {
      std::cerr << "--repetitions must be an integer\n";
      return 1;
    }
    std::cerr << "--repetitions=" << nRepetitions << std::endl;
  }
  int nSubflows = 1;
  if (line->HasSwitch("subflows")) {
      if (!base::StringToInt(line->GetSwitchValueASCII("subflows"), &nSubflows)) {
        std::cerr << "--subflows must be an integer\n";
        return 1;
      }
      if(nSubflows < 1) {
        std::cerr << "--subflows need at least one subflow\n";
        return 1;
      }
      std::cerr << "--subflows=" << nSubflows << std::endl;
    }
  bool disablePacing = false;
  if (line->HasSwitch("disable-pacing")) {
    disablePacing = true;
    std::cerr << "disable-pacing" << std::endl;
  }
  QuicMultipathConfiguration mpConfig =
      QuicMultipathConfiguration::CreateClientConfiguration(
          packetSchedulingMethod, ackHandlingMethod, clientPorts,
          clientIpAddress, !disablePacing);
  if(line->HasSwitch("disable-prr")) {
    MultipathSendAlgorithmInterface::noPrr = true;
    std::cerr << "disable-prr" << std::endl;
  }
  if(line->HasSwitch("enable-rate-based-sending")) {
    MultipathSendAlgorithmInterface::rateBasedSending = true;
    std::cerr << "enable-rate-based-sending" << std::endl;
  }
  if(line->HasSwitch("enable-slow-start-large-reduction")) {
    MultipathSendAlgorithmInterface::slowStartLargeReduction = true;
    std::cerr << "enable-slow-start-large-reduction" << std::endl;
  }
  if(line->HasSwitch("path-update-frequency")) {
    int path_frequency;
    if (!base::StringToInt(line->GetSwitchValueASCII("path-update-frequency"), &path_frequency)) {
      std::cerr << "--determine-path-frequency must be an integer\n";
      return 1;
    }
    OliaSendAlgorithm::pathUpdateFrequency = path_frequency;
    std::cerr << "path-update-frequency=" << path_frequency << std::endl;
  }
  if(line->HasSwitch("logging-type")) {
    if(line->GetSwitchValueASCII("logging-type") == "simple") {
      QuicConnection::LOG_STATS = true;
      std::cerr << "enable logging simple connection stats" << std::endl;
    } else if(line->GetSwitchValueASCII("logging-type") == "extensive") {
      QuicConnectionManagerLogger::ENABLED = true;
      std::cerr << "enable extensive logging" << std::endl;
    } else if(line->GetSwitchValueASCII("logging-type") == "full") {
      std::cerr << "enable logging simple connection stats" << std::endl;
      std::cerr << "enable extensive logging" << std::endl;
      QuicConnection::LOG_STATS = true;
      QuicConnectionManagerLogger::ENABLED = true;
    }
  }
  /*QuicBandwidth maxBandwidth = QuicBandwidth::Zero();
  if(line->HasSwitch("max-bandwidth")) {
    int b;
    if (!base::StringToInt(line->GetSwitchValueASCII("max-bandwidth"), &b)) {
      std::cerr << "--max-bandwidth must be an integer\n";
      return 1;
    }
    maxBandwidth = QuicBandwidth::FromKBitsPerSecond(b);
    QuicConnectionManager::MAX_BANDWIDTH = maxBandwidth;
    std::cerr << "max-bandwidth=" << maxBandwidth.ToKBitsPerSecond() << "Kbps" << std::endl;
  }*/


  VLOG(1)
      << "server host: " << FLAGS_host << " port: " << FLAGS_port << " body: "
          << FLAGS_body << " headers: " << FLAGS_headers << " quiet: "
          << FLAGS_quiet << " quic-version: " << FLAGS_quic_version
          << " version_mismatch_ok: " << FLAGS_version_mismatch_ok
          << " redirect_is_success: " << FLAGS_redirect_is_success
          << " initial_mtu: " << FLAGS_initial_mtu
          << " url: " << urls[0];

  base::AtExitManager exit_manager;
  base::MessageLoopForIO message_loop;

  // Determine IP address to connect to from supplied hostname.
  net::QuicIpAddress ip_addr;

  QuicUrl url(urls[0], "https");
  string host = FLAGS_host;
  if (host.empty()) {
    host = url.host();
  }
  int port = FLAGS_port;
  if (port == 0) {
    port = url.port();
  }
  if (!ip_addr.FromString(host)) {
    net::AddressList addresses;
    int rv = net::SynchronousHostResolver::Resolve(host, &addresses);
    if (rv != net::OK) {
      LOG(ERROR)
          << "Unable to resolve '" << host << "' : "
              << net::ErrorToShortString(rv);
      return 1;
    }
    ip_addr = net::QuicIpAddress(
        net::QuicIpAddressImpl(addresses[0].address()));
  }

  string host_port = net::QuicStrCat(ip_addr.ToString(), ":", port);
  VLOG(1) << "Resolved " << host << " to " << host_port << endl;

  // Build the client, and try to connect.
  net::EpollServer epoll_server;
  net::QuicServerId server_id(url.host(), url.port(),
      net::PRIVACY_MODE_DISABLED);
  net::QuicVersionVector versions = net::AllSupportedVersions();
  if (FLAGS_quic_version != -1) {
    versions.clear();
    versions.push_back(static_cast<net::QuicVersion>(FLAGS_quic_version));
  }
  // For secure QUIC we need to verify the cert chain.
  std::unique_ptr<CertVerifier> cert_verifier(CertVerifier::CreateDefault());
  std::unique_ptr<TransportSecurityState> transport_security_state(
      new TransportSecurityState);
  std::unique_ptr<MultiLogCTVerifier> ct_verifier(new MultiLogCTVerifier());
  ct_verifier->AddLogs(net::ct::CreateLogVerifiersForKnownLogs());
  std::unique_ptr<CTPolicyEnforcer> ct_policy_enforcer(new CTPolicyEnforcer());
  std::unique_ptr<ProofVerifier> proof_verifier;
  if (line->HasSwitch("disable-certificate-verification")) {
    proof_verifier.reset(new FakeProofVerifier());
  } else {
    proof_verifier.reset(
        new ProofVerifierChromium(cert_verifier.get(), ct_policy_enforcer.get(),
            transport_security_state.get(), ct_verifier.get()));
  }
  net::QuicMultipathClient client(net::QuicSocketAddress(ip_addr, port),
      server_id, versions, &epoll_server, std::move(proof_verifier));
  client.set_initial_max_packet_length(
      FLAGS_initial_mtu != 0 ? FLAGS_initial_mtu : net::kDefaultMaxPacketSize);
  if (!client.Initialize(mpConfig)) {
    cerr << "Failed to initialize client." << endl;
    return 1;
  }
  if (!client.Connect()) {
    net::QuicErrorCode error = client.session()->error();
    if (FLAGS_version_mismatch_ok && error == net::QUIC_INVALID_VERSION) {
      cout << "Server talks QUIC, but none of the versions supported by "
          << "this client: " << QuicVersionVectorToString(versions) << endl;
      // Version mismatch is not deemed a failure.
      return 0;
    }
    cerr << "Failed to connect to " << host_port << ". Error: "
        << net::QuicErrorCodeToString(error) << endl;
    return 1;
  }
  cout << "Connected to " << host_port << endl;

  //cout << "Adding subflow: " << endl;
  //client.AddSubflow();

  // Construct the string body from flags, if provided.
  string body = FLAGS_body;
  if (!FLAGS_body_hex.empty()) {
    DCHECK(FLAGS_body.empty()) << "Only set one of --body and --body_hex.";
    body = QuicTextUtils::HexDecode(FLAGS_body_hex);
  }

  // Construct a GET or POST request for supplied URL.
  SpdyHeaderBlock header_block;
  header_block[":method"] = body.empty() ? "GET" : "POST";
  header_block[":scheme"] = url.scheme();
  header_block[":authority"] = url.HostPort();
  header_block[":path"] = url.PathParamsQuery();

  // Append any additional headers supplied on the command line.
  for (QuicStringPiece sp : QuicTextUtils::Split(FLAGS_headers, ';')) {
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&sp);
    if (sp.empty()) {
      continue;
    }
    std::vector<QuicStringPiece> kv = QuicTextUtils::Split(sp, ':');
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[0]);
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[1]);
    header_block[kv[0]] = kv[1];
  }

  // Make sure to store the response, for later output.
  client.set_store_response(true);

  for(int i = 0;i < nSubflows-1; ++i) {
    cout << "++++++++++ Adding new subflow:" << endl;
    client.AddSubflow();
  }

  for (int i = 0; i < nRepetitions; ++i) {
    RequestSite(client, header_block, body,
        client.session()->connection_manager()->AnyConnection()->clock());
  }

  return Response(client);
}

#pragma once
// wirevault/subproc.hpp - spawn external commands with argv (no shell),
// capture stdout + exit status. Used to drive wg/nft/dnsmasq/fail2ban.
#include <string>
#include <vector>

namespace wv {

struct ProcResult {
  int exit_code = -1;
  std::string stdout_text;
  std::string stderr_text;
  bool ok() const { return exit_code == 0; }
};

// Runs argv[0] + args, waits for completion, returns captured output.
ProcResult runCommand(const std::vector<std::string> &argv,
                      const std::string &input = "", int timeout_ms = 15000);

} // namespace wv

// wirevault/subproc.cpp
#include "wirevault/subproc.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>

// Cross-platform-ish local pipe runner. On Linux this uses popen-free pipes;
// to keep the scaffold portable for the smoke-test we use a simple
// _popen/pclose on Windows and a fork/exec/wpopen on POSIX. The real
// deployment (Linux Mint/PiOS) uses the POSIX fork/exec path below.
#ifdef _WIN32
#include <windows.h>
#include <io.h>

namespace wv {
ProcResult runCommand(const std::vector<std::string> &argv,
                      const std::string & /*input*/, int /*timeout_ms*/) {
  // build "cmd /c <args>" for a quick port; production code uses POSIX path
  std::string cmd;
  for (size_t i = 0; i < argv.size(); ++i) {
    if (i) cmd += " ";
    cmd += "\"" + argv[i] + "\"";
  }
  FILE *p = _popen(cmd.c_str(), "r");
  ProcResult r;
  if (!p) {
    r.exit_code = -1;
    return r;
  }
  char buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof buf - 1, p)) > 0) {
    buf[n] = 0;
    r.stdout_text += buf;
  }
  int rc = _pclose(p);
  r.exit_code = rc;
  return r;
}
} // namespace wv

#else
#include <sys/wait.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <cerrno>

namespace wv {
ProcResult runCommand(const std::vector<std::string> &argv,
                      const std::string & /*input*/, int timeout_ms) {
  ProcResult r;
  if (argv.empty()) {
    r.exit_code = -1;
    return r;
  }
  int out_pipe[2];
  if (pipe(out_pipe) != 0) {
    r.exit_code = -1;
    return r;
  }
  pid_t pid = fork();
  if (pid < 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    r.exit_code = -1;
    return r;
  }
  if (pid == 0) {
    // child
    close(out_pipe[0]);
    dup2(out_pipe[1], STDOUT_FILENO);
    dup2(out_pipe[1], STDERR_FILENO);
    close(out_pipe[1]);
    std::vector<char *> cargv;
    cargv.reserve(argv.size() + 1);
    for (const auto &a : argv)
      cargv.push_back(const_cast<char *>(a.c_str()));
    cargv.push_back(nullptr);
    execvp(cargv[0], cargv.data());
    _exit(127); // exec failed
  }
  close(out_pipe[1]);
  // read with timeout
  char buf[4096];
  time_t start = time(nullptr);
  int rc = -1;
  while (true) {
    int remain = timeout_ms > 0 ? timeout_ms - (int)((time(nullptr) - start) * 1000) : -1;
    if (remain < 0)
      break;
    pollfd pfd = {out_pipe[0], POLLIN, 0};
    int pr = poll(&pfd, 1, remain);
    if (pr == 0)
      break; // timeout
    if (pr < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    ssize_t n = read(out_pipe[0], buf, sizeof buf - 1);
    if (n <= 0)
      break;
    buf[n] = 0;
    r.stdout_text += buf;
  }
  // wait with timeout
  pid_t w;
  do {
    w = waitpid(pid, &rc, WNOHANG);
    if (w == 0) {
      usleep(50 * 1000);
      continue;
    }
  } while (w == 0);
  if (w == pid) {
    if (WIFEXITED(rc))
      r.exit_code = WEXITSTATUS(rc);
    else
      r.exit_code = 128 + (WIFSIGNALED(rc) ? WTERMSIG(rc) : 0);
  } else {
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
    r.exit_code = -2; // timed out
  }
  close(out_pipe[0]);
  return r;
}
} // namespace wv
#endif

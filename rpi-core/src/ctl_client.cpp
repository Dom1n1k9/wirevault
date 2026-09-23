// wirevault/ctl_client.cpp
#include "wirevault/ctl_client.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netdb.h>
#endif

#include <cstring>
#include <memory>
#include <string>

#include "wirevault/logging.hpp"

namespace wv {

CtlClient::CtlClient(std::string sockPath, std::string host, int port)
    : sockPath_(std::move(sockPath)), host_(std::move(host)), port_(port) {}

Json CtlClient::request(const std::string &method, const Json &params) {
  Json req(Json::Object{});
  req.set("id", Json(std::string("cli")));
  req.set("method", Json(method));
  req.set("params", params);
  std::string out = req.dump() + "\n";

  int fd = -1;
#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
  if (!host_.empty() && port_ > 0) {
    fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port_);
    inet_pton(AF_INET, host_.c_str(), &addr.sin_addr);
    if (connect(fd, (sockaddr *)&addr, sizeof addr) != 0) {
      closesocket(fd);
      return Json(Json::Object{{"error", Json(std::string("connect failed"))}});
    }
  } else {
    closesocket(fd);
    return Json(Json::Object{{"error", Json(std::string("windows needs host:port"))}});
  }
#else
  if (!host_.empty() && port_ > 0) {
    fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port_);
    if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) != 1 ||
        connect(fd, (sockaddr *)&addr, sizeof addr) != 0) {
      close(fd);
      return Json(Json::Object{{"error", Json(std::string("connect failed"))}});
    }
  } else {
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockPath_.c_str(), sizeof addr.sun_path - 1);
    if (connect(fd, (sockaddr *)&addr, sizeof addr) != 0) {
      close(fd);
      return Json(Json::Object{{"error", Json(std::string("connect failed to " + sockPath_))}});
    }
  }
#endif

  // send request
#ifdef _WIN32
  ::send(fd, out.data(), (int)out.size(), 0);
#else
  ::write(fd, out.data(), out.size());
#endif

  // read response (newline terminated, cap size)
  std::string buf;
  char tmp[1024];
  while (true) {
#ifdef _WIN32
    int n = ::recv(fd, tmp, sizeof tmp - 1, 0);
#else
    ssize_t n = ::read(fd, tmp, sizeof tmp - 1);
#endif
    if (n <= 0)
      break;
    tmp[n] = 0;
    buf += tmp;
    if (buf.find('\n') != std::string::npos || buf.size() > (1 << 20))
      break;
  }
#ifdef _WIN32
  closesocket(fd);
#else
  close(fd);
#endif

  if (buf.empty())
    return Json(Json::Object{{"error", Json(std::string("no reply"))}});
  try {
    return Json::parse(buf);
  } catch (const std::exception &ex) {
    return Json(Json::Object{{"error", Json(std::string("bad reply: ") + ex.what())}});
  }
}

} // namespace wv

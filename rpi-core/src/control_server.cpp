// wirevault/control_server.cpp
#include "wirevault/control_server.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "wirevault/logging.hpp"

namespace wv {

struct ControlServer::Impl {
  std::string path;
  RequestHandler handler;
  int listen_fd = -1;
  bool running = false;
  std::thread accept_thread;
  std::vector<int> clients;
  std::mutex cli_mtx;

  // respond helper
  static void sendAll(int fd, const std::string &s) {
#ifdef _WIN32
    ::send(fd, s.data(), (int)s.size(), 0);
#else
    ::write(fd, s.data(), s.size());
#endif
  }
};

ControlServer::ControlServer(const std::string &sockPath, RequestHandler handler)
    : impl_(new Impl) {
  impl_->path = sockPath;
  impl_->handler = std::move(handler);
}

ControlServer::~ControlServer() { stop(); }

void ControlServer::start() {
#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
  // on Windows this scaffold uses a TCP loopback : custom port for testing
  impl_->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(18080);
  if (bind(impl_->listen_fd, (sockaddr *)&addr, sizeof addr) == 0)
    listen(impl_->listen_fd, 4);
#else
  impl_->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, impl_->path.c_str(), sizeof addr.sun_path - 1);
  unlink(impl_->path.c_str());
  if (bind(impl_->listen_fd, (sockaddr *)&addr, sizeof addr) < 0) {
    WV_ERROR("bind %s failed", impl_->path.c_str());
    return;
  }
  chmod(impl_->path.c_str(), 0700);
  listen(impl_->listen_fd, 4);
#endif
  impl_->running = true;
  impl_->accept_thread = std::thread([this]() {
    while (impl_->running) {
      int c = ::accept(impl_->listen_fd, nullptr, nullptr);
      if (c < 0)
        break;
      {
        std::lock_guard<std::mutex> lk(impl_->cli_mtx);
        impl_->clients.push_back(c);
      }
      std::thread([this, c]() {
        char buf[4096];
        while (impl_->running) {
          ssize_t n;
#ifdef _WIN32
          n = ::recv(c, buf, sizeof buf - 1, 0);
#else
          n = ::read(c, buf, sizeof buf - 1);
#endif
          if (n <= 0)
            break;
          buf[n] = 0;
          std::string req(buf, (size_t)n);
          std::string err;
          Json result;
          try {
            Json j = Json::parse(req);
            Json params = j.at("params", Json(Json::Object{}));
            result = impl_->handler(j.at("method", Json(std::string{})).asStr(),
                                    params, err);
          } catch (const std::exception &ex) {
            err = ex.what();
          }
          Json resp(Json::Object{});
          if (err.empty())
            resp.set("result", result);
          else
            resp.set("error", Json(err));
          Impl::sendAll(c, resp.dump() + "\n");
        }
        {
          std::lock_guard<std::mutex> lk(impl_->cli_mtx);
          auto it = std::find(impl_->clients.begin(), impl_->clients.end(), c);
          if (it != impl_->clients.end())
            impl_->clients.erase(it);
        }
#ifdef _WIN32
        closesocket(c);
#else
        close(c);
#endif
      }).detach();
    }
  });
}

void ControlServer::stop() {
  if (!impl_->running)
    return;
  impl_->running = false;
  // close listener to wake accept
#ifdef _WIN32
  closesocket(impl_->listen_fd);
#else
  close(impl_->listen_fd);
  unlink(impl_->path.c_str());
#endif
  if (impl_->accept_thread.joinable())
    impl_->accept_thread.join();
}

void ControlServer::broadcast(const std::string &event, const Json &data) {
  Json ev(Json::Object{});
  ev.set("event", Json(event));
  ev.set("data", data);
  std::string out = ev.dump() + "\n";
  std::lock_guard<std::mutex> lk(impl_->cli_mtx);
  for (int c : impl_->clients)
    Impl::sendAll(c, out);
}

} // namespace wv

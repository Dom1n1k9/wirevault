#pragma once
// wirevault/event_bus.hpp - thread-safe pub/sub for daemon-internal events.
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "wirevault/json.hpp"

namespace wv {

using Handler = std::function<void(const std::string & /*event*/, const Json &/*data*/)>;

class EventBus {
public:
  void subscribe(const std::string &event, Handler h) {
    std::lock_guard<std::mutex> lk(mtx_);
    subs_[event].push_back(std::move(h));
  }
  void unsubscribeAll() {
    std::lock_guard<std::mutex> lk(mtx_);
    subs_.clear();
  }
  void publish(const std::string &event, const Json &data) {
    std::vector<Handler> copy;
    {
      std::lock_guard<std::mutex> lk(mtx_);
      auto it = subs_.find(event);
      if (it != subs_.end())
        copy = it->second;
    }
    for (auto &h : copy)
      h(event, data);
  }

private:
  std::map<std::string, std::vector<Handler>> subs_;
  std::mutex mtx_;
};

} // namespace wv

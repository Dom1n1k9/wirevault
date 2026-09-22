#pragma once
// wirevault/incident_store.hpp - SQLite audit trail (incidents/alerts/events).
#include <memory>
#include <string>
#include <vector>

#include "wirevault/json.hpp"

namespace wv {

struct Incident {
  int64_t id = 0;
  int64_t ts = 0;
  std::string kind;      // "wg_apply" | "rule_change" | "threat" | "ack" | ...
  std::string severity;  // info | warning | critical
  std::string summary;
  std::string detail;    // JSON blob
  int acked = 0;
};

class IncidentStore {
public:
  explicit IncidentStore(const std::string &path);
  ~IncidentStore();

  // table is created on open; returns false on sqlite error
  bool ok() const;
  int64_t add(const std::string &kind, const std::string &severity,
              const std::string &summary, const Json &detail);
  std::vector<Incident> recent(int limit, int64_t since = 0);
  bool ack(int64_t id);
  int64_t lastInsertedId() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace wv

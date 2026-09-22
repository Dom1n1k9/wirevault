// wirevault/incident_store.cpp
#include "wirevault/incident_store.hpp"

#include <sqlite3.h>
#include <ctime>
#include <string>
#include <vector>

#include "wirevault/logging.hpp"

namespace wv {

struct IncidentStore::Impl {
  sqlite3 *db = nullptr;
  bool ok_ = false;
};

IncidentStore::IncidentStore(const std::string &path) : impl_(new Impl) {
  if (sqlite3_open(path.c_str(), &impl_->db) != SQLITE_OK) {
    WV_ERROR("sqlite open failed for %s: %s", path.c_str(),
             impl_->db ? sqlite3_errmsg(impl_->db) : "no db");
    return;
  }
  const char *ddl =
      "CREATE TABLE IF NOT EXISTS incidents ("
      " id INTEGER PRIMARY KEY AUTOINCREMENT,"
      " ts INTEGER NOT NULL,"
      " kind TEXT NOT NULL,"
      " severity TEXT NOT NULL,"
      " summary TEXT NOT NULL,"
      " detail TEXT NOT NULL,"
      " acked INTEGER NOT NULL DEFAULT 0);";

  char *err = nullptr;
  if (sqlite3_exec(impl_->db, ddl, nullptr, nullptr, &err) != SQLITE_OK) {
    WV_ERROR("schema: %s", err ? err : "unknown");
    if (err)
      sqlite3_free(err);
    return;
  }
  impl_->ok_ = true;
}

IncidentStore::~IncidentStore() {
  if (impl_ && impl_->db)
    sqlite3_close(impl_->db);
}

bool IncidentStore::ok() const { return impl_->ok_; }

int64_t IncidentStore::add(const std::string &kind, const std::string &severity,
                           const std::string &summary, const Json &detail) {
  if (!ok())
    return -1;
  const char *sql =
      "INSERT INTO incidents (ts, kind, severity, summary, detail) VALUES (?,?,?,?,?)";
  sqlite3_stmt *st = nullptr;
  if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK)
    return -1;
  sqlite3_bind_int64(st, 1, (sqlite3_int64)time(nullptr));
  sqlite3_bind_text(st, 2, kind.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 3, severity.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 4, summary.c_str(), -1, SQLITE_TRANSIENT);
  std::string d = detail.dump();
  sqlite3_bind_text(st, 5, d.c_str(), -1, SQLITE_TRANSIENT);
  int rc = sqlite3_step(st);
  int64_t id = -1;
  if (rc == SQLITE_DONE)
    id = sqlite3_last_insert_rowid(impl_->db);
  sqlite3_finalize(st);
  return id;
}

std::vector<Incident> IncidentStore::recent(int limit, int64_t since) {
  std::vector<Incident> out;
  if (!ok() || limit <= 0)
    return out;
  sqlite3_stmt *st = nullptr;
  if (sqlite3_prepare_v2(impl_->db,
                         "SELECT id,ts,kind,severity,summary,detail,acked FROM incidents"
                         " WHERE ts >= ? ORDER BY id DESC LIMIT ?",
                         -1, &st, nullptr) != SQLITE_OK)
    return out;
  sqlite3_bind_int64(st, 1, (sqlite3_int64)since);
  sqlite3_bind_int(st, 2, limit);
  while (sqlite3_step(st) == SQLITE_ROW) {
    Incident in;
    in.id = sqlite3_column_int64(st, 0);
    in.ts = sqlite3_column_int64(st, 1);
    if (sqlite3_column_type(st, 2) == SQLITE_TEXT)
      in.kind = (const char *)sqlite3_column_text(st, 2);
    if (sqlite3_column_type(st, 3) == SQLITE_TEXT)
      in.severity = (const char *)sqlite3_column_text(st, 3);
    if (sqlite3_column_type(st, 4) == SQLITE_TEXT)
      in.summary = (const char *)sqlite3_column_text(st, 4);
    if (sqlite3_column_type(st, 5) == SQLITE_TEXT)
      in.detail = (const char *)sqlite3_column_text(st, 5);
    in.acked = sqlite3_column_int(st, 6);
    out.push_back(std::move(in));
  }
  sqlite3_finalize(st);
  if (out.size() > (size_t)limit)
    out.resize((size_t)limit);
  return out;
}

bool IncidentStore::ack(int64_t id) {
  if (!ok())
    return false;
  sqlite3_stmt *st = nullptr;
  if (sqlite3_prepare_v2(impl_->db, "UPDATE incidents SET acked=1 WHERE id=?",
                         -1, &st, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int64(st, 1, id);
  int rc = sqlite3_step(st);
  sqlite3_finalize(st);
  return rc == SQLITE_DONE;
}

} // namespace wv

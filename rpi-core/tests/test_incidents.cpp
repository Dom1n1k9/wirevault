// tests/test_incidents.cpp - incident store SQLite round-trip.
#include <cassert>
#include <cstdio>
#include <iostream>
#include <string>

#include "wirevault/incident_store.hpp"

using namespace wv;

int main() {
  const char *dbpath = "./wirevault_test_incidents.db";
  remove(dbpath);

  {
    IncidentStore store(dbpath);
    assert(store.ok());
    int64_t id = store.add("threat", "critical", "test alert",
                           Json(Json::Object{{"sig", Json(std::string("x"))}}));
    assert(id > 0);
    auto rows = store.recent(10);
    assert(rows.size() == 1);
    assert(rows[0].kind == "threat");
    assert(rows[0].severity == "critical");
    assert(rows[0].acked == 0);
    assert(store.ack(rows[0].id));
  }

  // reopen -> persisted
  {
    IncidentStore store(dbpath);
    auto rows = store.recent(10);
    assert(rows.size() == 1);
    assert(rows[0].acked == 1);
  }
  remove(dbpath);

  std::cout << "INCIDENT TESTS PASSED\n";
  return 0;
}

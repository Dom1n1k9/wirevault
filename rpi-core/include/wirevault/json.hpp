#pragma once
// wirevault/json.hpp - minimal header-only JSON for the control daemon.
// Same shape as the GUI protocol: small, dependency-free, RFC 8259 subset.
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace wv {

class Json {
public:
  using Array = std::vector<Json>;
  using Object = std::map<std::string, Json>;
  using Value = std::variant<std::nullptr_t, bool, double, int64_t, std::string,
                             Array, Object>;

  Json() : v_(nullptr) {}
  Json(std::nullptr_t) : v_(nullptr) {}
  Json(bool b) : v_(b) {}
  Json(double d) : v_(d) {}
  Json(int i) : v_(static_cast<int64_t>(i)) {}
  Json(int64_t i) : v_(i) {}
  Json(const char *s) : v_(std::string(s)) {}
  Json(std::string s) : v_(std::move(s)) {}
  Json(Array a) : v_(std::move(a)) {}
  Json(Object o) : v_(std::move(o)) {}

  static Json parse(const std::string &text) {
    Parser p(text);
    Json j = p.parseValue();
    p.skipWs();
    if (!p.atEnd())
      throw std::runtime_error("json: trailing characters");
    return j;
  }

  bool isNull() const { return std::holds_alternative<std::nullptr_t>(v_); }
  bool isBool() const { return std::holds_alternative<bool>(v_); }
  bool isNumber() const {
    return std::holds_alternative<double>(v_) ||
           std::holds_alternative<int64_t>(v_);
  }
  bool isString() const { return std::holds_alternative<std::string>(v_); }
  bool isArray() const { return std::holds_alternative<Array>(v_); }
  bool isObject() const { return std::holds_alternative<Object>(v_); }

  bool asBool(bool def = false) const {
    if (auto *b = std::get_if<bool>(&v_))
      return *b;
    return def;
  }
  double asNumber(double def = 0.0) const {
    if (auto *d = std::get_if<double>(&v_))
      return *d;
    if (auto *i = std::get_if<int64_t>(&v_))
      return static_cast<double>(*i);
    return def;
  }
  int64_t asInt(int64_t def = 0) const {
    if (auto *i = std::get_if<int64_t>(&v_))
      return *i;
    if (auto *d = std::get_if<double>(&v_))
      return static_cast<int64_t>(*d);
    return def;
  }
  const std::string &asStr(const std::string &def = "") const {
    if (auto *s = std::get_if<std::string>(&v_))
      return *s;
    return def;
  }
  // by-value to avoid lifetime traps on .at() temporaries
  Array asArray() const {
    if (auto *a = std::get_if<Array>(&v_))
      return *a;
    return Array{};
  }
  Object asObject() const {
    if (auto *o = std::get_if<Object>(&v_))
      return *o;
    return Object{};
  }

  bool has(const std::string &key) const {
    auto *o = std::get_if<Object>(&v_);
    return o && o->count(key);
  }
  Json at(const std::string &key) const {
    auto *o = std::get_if<Object>(&v_);
    if (!o)
      throw std::runtime_error("json: not an object");
    auto it = o->find(key);
    if (it == o->end())
      throw std::runtime_error("json: missing key " + key);
    return it->second;
  }
  Json at(const std::string &key, const Json &def) const {
    auto *o = std::get_if<Object>(&v_);
    if (!o)
      return def;
    auto it = o->find(key);
    if (it == o->end())
      return def;
    return it->second;
  }
  Json at(size_t idx) const {
    auto *a = std::get_if<Array>(&v_);
    if (!a || idx >= a->size())
      throw std::runtime_error("json: array index out of range");
    return (*a)[idx];
  }

  void set(const std::string &key, Json val) {
    if (!isObject())
      v_ = Object{};
    std::get<Object>(v_)[key] = std::move(val);
  }

  // array mutation helpers
  void push_back(Json val) {
    if (!isArray())
      v_ = Array{};
    std::get<Array>(v_).push_back(std::move(val));
  }
  size_t size() const {
    if (auto *a = std::get_if<Array>(&v_))
      return a->size();
    return 0;
  }

  std::string dump() const { return serialize(v_, 0); }

private:
  struct Parser {
    const std::string &s;
    size_t i = 0;
    explicit Parser(const std::string &text) : s(text) {}
    bool atEnd() const { return i >= s.size(); }
    void skipWs() {
      while (i < s.size() && std::isspace((unsigned char)s[i]))
        ++i;
    }
    char peek() {
      skipWs();
      if (atEnd())
        throw std::runtime_error("json: unexpected end");
      return s[i];
    }
    char consume() {
      char c = peek();
      ++i;
      return c;
    }
    Json parseValue() {
      char c = peek();
      if (c == '{') return parseObject();
      if (c == '[') return parseArray();
      if (c == '"') return Json(parseString());
      if (skipLit("true")) return Json(true);
      if (skipLit("false")) return Json(false);
      if (skipLit("null")) return Json(nullptr);
      return parseNumber();
    }
    bool skipLit(const std::string &l) {
      skipWs();
      if (s.compare(i, l.size(), l) == 0) { i += l.size(); return true; }
      return false;
    }
    std::string parseString() {
      if (consume() != '"') throw std::runtime_error("json: expected string");
      std::string out;
      while (!atEnd()) {
        char c = s[i++];
        if (c == '"') return out;
        if (c == '\\') {
          if (atEnd()) break;
          char e = s[i++];
          switch (e) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
              uint32_t cp = 0;
              for (int k = 0; k < 4; ++k) { if (atEnd()) break; cp = (cp << 4) | hexv(s[i++]); }
              if (cp < 0x80) out += (char)cp;
              else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
              else { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
              break;
            }
            default: throw std::runtime_error("json: bad escape");
          }
        } else out += c;
      }
      throw std::runtime_error("json: unterminated string");
    }
    static int hexv(char c) {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      throw std::runtime_error("json: bad hex");
    }
    Json parseNumber() {
      skipWs();
      size_t start = i;
      if (i < s.size() && s[i] == '-') ++i;
      bool floating = false;
      while (i < s.size() && (isdigit((unsigned char)s[i]) || s[i]=='.' ||
                              s[i]=='e' || s[i]=='E' || s[i]=='+' || s[i]=='-')) {
        if (s[i]=='.' || s[i]=='e' || s[i]=='E') floating = true;
        ++i;
      }
      if (start == i) throw std::runtime_error("json: malformed number");
      std::string tok = s.substr(start, i - start);
      if (floating) return Json(std::stod(tok));
      return Json((int64_t)std::stoll(tok));
    }
    Json parseObject() {
      consume();
      Object o;
      skipWs();
      if (!atEnd() && s[i]=='}') { ++i; return Json(o); }
      while (true) {
        skipWs();
        std::string k = parseString();
        skipWs();
        if (consume() != ':') throw std::runtime_error("json: expected ':'");
        o.emplace(std::move(k), parseValue());
        skipWs();
        char c = consume();
        if (c=='}') break;
        if (c!=',') throw std::runtime_error("json: expected ',' or '}'");
      }
      return Json(o);
    }
    Json parseArray() {
      consume();
      Array a;
      skipWs();
      if (!atEnd() && s[i]==']') { ++i; return Json(a); }
      while (true) {
        a.push_back(parseValue());
        skipWs();
        char c = consume();
        if (c==']') break;
        if (c!=',') throw std::runtime_error("json: expected ',' or ']'");
      }
      return Json(a);
    }
  };

  static std::string serialize(const Value &v, int) {
    if (std::holds_alternative<std::nullptr_t>(v)) return "null";
    if (auto *b = std::get_if<bool>(&v)) return *b ? "true" : "false";
    if (auto *i = std::get_if<int64_t>(&v)) return std::to_string(*i);
    if (auto *d = std::get_if<double>(&v)) {
      if (std::isnan(*d) || std::isinf(*d)) return "0";
      return std::to_string(*d);
    }
    if (auto *s = std::get_if<std::string>(&v)) return serStr(*s);
    if (auto *a = std::get_if<Array>(&v)) {
      std::string out = "[";
      for (size_t k = 0; k < a->size(); ++k) {
        if (k) out += ",";
        out += serialize((*a)[k].v_, 0);
      }
      return out + "]";
    }
    if (auto *o = std::get_if<Object>(&v)) {
      std::string out = "{";
      size_t k = 0;
      for (const auto &[key, val] : *o) {
        if (k++) out += ",";
        out += serStr(key) + ":" + serialize(val.v_, 0);
      }
      return out + "}";
    }
    return "null";
  }
  static std::string serStr(const std::string &s) {
    std::string out = "\"";
    for (char c : s) {
      switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
          if ((unsigned char)c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); out += b; }
          else out += c;
      }
    }
    return out + "\"";
  }

  Value v_;
};

} // namespace wv

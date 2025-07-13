// Copyright 2025 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

#include "time_zone_icu_win.h"

#if defined(_WIN32)

#if !defined(NOMINMAX)
#define NOMINMAX
#endif  // !defined(NOMINMAX)
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "time_zone_if.h"
#include "tzfile.h"
#include "cctz/zone_info_source.h"

namespace cctz {
namespace {

// We reject leap-second encoded zoneinfo and so assume 60-second minutes.
const std::int32_t kSecsPerDay = 24 * 60 * 60;

// 400-year chunks always have 146097 days (20871 weeks).
const std::int64_t kSecsPer400Years = 146097LL * kSecsPerDay;

using UBool = uint8_t;
using UCalendar = void;
using UChar = int16_t;
using UDate = double;

enum UErrorCode : int32_t {
  U_ZERO_ERROR = 0,
  U_BUFFER_OVERFLOW_ERROR = 15,
  U_UNSUPPORTED_ERROR = 16
};

enum UCalendarDateFields : int32_t {
  UCAL_ZONE_OFFSET = 15,
  UCAL_DST_OFFSET = 16
};

enum UCalendarType : int32_t {
  UCAL_GREGORIAN = 0,
};

enum UCalendarDisplayNameType : int32_t {
  UCAL_SHORT_STANDARD = 1,
  UCAL_SHORT_DST = 3
};

enum UTimeZoneTransitionType : int32_t {
  UCAL_TZ_TRANSITION_NEXT = 0,
};

// ICU function signatures
using ucal_close_func = void (__cdecl *)(UCalendar* cal);
using ucal_get_func = int32_t (__cdecl *)(const UCalendar* cal, UCalendarDateFields field, UErrorCode* status);
using ucal_getCanonicalTimeZoneID_func = int32_t (__cdecl *)(const UChar* id, int32_t len, UChar* result, int32_t resultCapacity, UBool* isSystemID, UErrorCode* status);
using ucal_getTimeZoneDisplayName_func = int32_t (__cdecl *)(const UCalendar* cal, UCalendarDisplayNameType type, const char* locale, UChar* result, int32_t resultLength, UErrorCode* status);
using ucal_getTimeZoneTransitionDate_func = UBool (__cdecl *)(const UCalendar* cal, UTimeZoneTransitionType type, UDate* transition, UErrorCode* status);
using ucal_getTZDataVersion_func = const char* (__cdecl *)(UErrorCode* status);
using ucal_open_func = UCalendar* (__cdecl *)(const UChar* zoneID, int32_t len, const char* locale, UCalendarType caltype, UErrorCode* status);
using ucal_setMillis_func = void (__cdecl *)(UCalendar* cal, UDate dateTime, UErrorCode* status);
using ucal_getMillis_func = UDate (__cdecl *)(const UCalendar* cal, UErrorCode* status);
using ucal_getHostTimeZone_func = int32_t (__cdecl *)(UChar* result, int32_t resultCapacity, UErrorCode* status);
using ucal_getTimeZoneIDForWindowsID_func = int32_t (__cdecl *)(const UChar* winid, int32_t len, const char* region, UChar* id, int32_t idCapacity, UErrorCode* status);
using ScopedUCalendar = std::unique_ptr<UCalendar, ucal_close_func>;

constexpr bool U_SUCCESS(UErrorCode error) {
  return error <= U_ZERO_ERROR;
}

constexpr bool U_FAILURE(UErrorCode error) {
  return error > U_ZERO_ERROR;
}

// ICU function pointers - loaded dynamically
static std::atomic<ucal_close_func> g_ucal_close;
static std::atomic<ucal_get_func> g_ucal_get;
static std::atomic<ucal_getCanonicalTimeZoneID_func> g_ucal_getCanonicalTimeZoneID;
static std::atomic<ucal_getTimeZoneDisplayName_func> g_ucal_getTimeZoneDisplayName;
static std::atomic<ucal_getTimeZoneTransitionDate_func> g_ucal_getTimeZoneTransitionDate;
static std::atomic<ucal_getTZDataVersion_func> g_ucal_getTZDataVersion;
static std::atomic<ucal_open_func> g_ucal_open;
static std::atomic<ucal_setMillis_func> g_ucal_setMillis;
static std::atomic<ucal_getMillis_func> g_ucal_getMillis;
static std::atomic<ucal_getHostTimeZone_func> g_ucal_getHostTimeZone;
static std::atomic<ucal_getTimeZoneIDForWindowsID_func> g_ucal_getTimeZoneIDForWindowsID;
static std::atomic<bool> g_unavailable;

struct IcuFunctions {
  bool available;
  ucal_close_func ucal_close;
  ucal_get_func ucal_get;
  ucal_getCanonicalTimeZoneID_func ucal_getCanonicalTimeZoneID;
  ucal_getTimeZoneDisplayName_func ucal_getTimeZoneDisplayName;
  ucal_getTimeZoneTransitionDate_func ucal_getTimeZoneTransitionDate;
  ucal_getTZDataVersion_func ucal_getTZDataVersion;
  ucal_open_func ucal_open;
  ucal_setMillis_func ucal_setMillis;
  ucal_getMillis_func ucal_getMillis;
  ucal_getHostTimeZone_func ucal_getHostTimeZone;
  ucal_getTimeZoneIDForWindowsID_func ucal_getTimeZoneIDForWindowsID;

  static IcuFunctions Unavailable() {
    return {false, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
  }
};

// Convert UTF-8 string to UChar array (UTF-16)
std::pair<std::unique_ptr<UChar[]>, int> ToUChars(const std::string& utf8str) {
  if (utf8str.size() > std::numeric_limits<int>::max()) {
    return std::make_pair(nullptr, 0);
  }
  const int utf8str_len = static_cast<int>(utf8str.size());

  const int num_counts = ::MultiByteToWideChar(
      CP_UTF8, MB_ERR_INVALID_CHARS, utf8str.data(), utf8str_len, nullptr, 0);
  if (num_counts <= 0) {
    return std::make_pair(nullptr, 0);
  }
  if (num_counts == std::numeric_limits<int>::max()) {
    return std::make_pair(nullptr, 0);
  }
  const int num_counts_with_null = num_counts + 1;
  std::unique_ptr<UChar[]> ustr =
      std::make_unique<UChar[]>(num_counts_with_null);
  const int written_counts = ::MultiByteToWideChar(
      CP_UTF8, MB_ERR_INVALID_CHARS, utf8str.data(), utf8str_len,
      reinterpret_cast<wchar_t*>(ustr.get()), num_counts_with_null);
  if (num_counts != written_counts) {
    return std::make_pair(nullptr, 0);
  }
  return std::make_pair(std::move(ustr), num_counts);
}

// Convert UChar array (UTF-16) to UTF-8 string
std::string FromUChars(const UChar* ptr, size_t size) {
  if (size > std::numeric_limits<int>::max()) {
    return "";
  }
  const int uchars_len = static_cast<int>(size);
  const wchar_t* uchars = reinterpret_cast<const wchar_t*>(ptr);
  const int num_bytes_in_utf8 =
      ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, uchars, uchars_len,
                            nullptr, 0, nullptr, nullptr);
  if (num_bytes_in_utf8 <= 0) {
    return std::string();
  }

  std::string utf8;
  utf8.resize(static_cast<size_t>(num_bytes_in_utf8));
  const int num_written_bytes =
      ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, uchars, uchars_len,
                            &utf8[0], num_bytes_in_utf8, nullptr, nullptr);
  if (num_written_bytes != num_bytes_in_utf8) {
    return std::string();
  }
  return utf8;
}

// Load ICU functions dynamically
IcuFunctions GetIcuFunctions() {
  if (g_unavailable.load(std::memory_order_relaxed)) {
    return IcuFunctions::Unavailable();
  }

  // Check if already loaded
  {
    const auto ucal_closeRef = g_ucal_close.load(std::memory_order_relaxed);
    const auto ucal_getRef = g_ucal_get.load(std::memory_order_relaxed);
    const auto ucal_getCanonicalTimeZoneIDRef =
        g_ucal_getCanonicalTimeZoneID.load(std::memory_order_relaxed);
    const auto ucal_getTimeZoneDisplayNameRef =
        g_ucal_getTimeZoneDisplayName.load(std::memory_order_relaxed);
    const auto ucal_getTimeZoneTransitionDateRef =
        g_ucal_getTimeZoneTransitionDate.load(std::memory_order_relaxed);
    const auto ucal_getTZDataVersionRef =
        g_ucal_getTZDataVersion.load(std::memory_order_relaxed);
    const auto ucal_openRef = g_ucal_open.load(std::memory_order_relaxed);
    const auto ucal_setMillisRef =
        g_ucal_setMillis.load(std::memory_order_relaxed);
    const auto ucal_getMillisRef =
        g_ucal_getMillis.load(std::memory_order_relaxed);
    const auto ucal_getHostTimeZoneRef =
        g_ucal_getHostTimeZone.load(std::memory_order_relaxed);
    const auto ucal_getTimeZoneIDForWindowsIDRef =
        g_ucal_getTimeZoneIDForWindowsID.load(std::memory_order_relaxed);

    if (ucal_closeRef != nullptr && ucal_getRef != nullptr &&
        ucal_getCanonicalTimeZoneIDRef != nullptr &&
        ucal_getTimeZoneDisplayNameRef != nullptr &&
        ucal_getTimeZoneTransitionDateRef != nullptr &&
        ucal_getTZDataVersionRef != nullptr && ucal_openRef != nullptr &&
        ucal_setMillisRef != nullptr &&
        ucal_getMillisRef != nullptr &&
        ucal_getHostTimeZoneRef != nullptr && ucal_getTimeZoneIDForWindowsIDRef != nullptr) {
      return {true, ucal_closeRef, ucal_getRef, ucal_getCanonicalTimeZoneIDRef,
              ucal_getTimeZoneDisplayNameRef, ucal_getTimeZoneTransitionDateRef,
              ucal_getTZDataVersionRef, ucal_openRef,
              ucal_setMillisRef, ucal_getMillisRef, ucal_getHostTimeZoneRef,
              ucal_getTimeZoneIDForWindowsIDRef};
    }
  }

  const HMODULE icudll =
      ::LoadLibraryExW(L"icu.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (icudll == nullptr) {
    g_unavailable.store(true, std::memory_order_relaxed);
    return IcuFunctions::Unavailable();
  }

  const auto ucal_closeRef = reinterpret_cast<ucal_close_func>(::GetProcAddress(icudll, "ucal_close"));
  const auto ucal_getRef = reinterpret_cast<ucal_get_func>(::GetProcAddress(icudll, "ucal_get"));
  const auto ucal_getCanonicalTimeZoneIDRef = reinterpret_cast<ucal_getCanonicalTimeZoneID_func>(::GetProcAddress(icudll, "ucal_getCanonicalTimeZoneID"));
  const auto ucal_getTimeZoneDisplayNameRef = reinterpret_cast<ucal_getTimeZoneDisplayName_func>(::GetProcAddress(icudll, "ucal_getTimeZoneDisplayName"));
  const auto ucal_getTimeZoneTransitionDateRef = reinterpret_cast<ucal_getTimeZoneTransitionDate_func>(::GetProcAddress(icudll, "ucal_getTimeZoneTransitionDate"));
  const auto ucal_getTZDataVersionRef = reinterpret_cast<ucal_getTZDataVersion_func>(::GetProcAddress(icudll, "ucal_getTZDataVersion"));
  const auto ucal_openRef = reinterpret_cast<ucal_open_func>(::GetProcAddress(icudll, "ucal_open"));
  const auto ucal_setMillisRef = reinterpret_cast<ucal_setMillis_func>(::GetProcAddress(icudll, "ucal_setMillis"));
  const auto ucal_getMillisRef = reinterpret_cast<ucal_getMillis_func>(::GetProcAddress(icudll, "ucal_getMillis"));
  auto ucal_getHostTimeZoneRef = reinterpret_cast<ucal_getHostTimeZone_func>(::GetProcAddress(icudll, "ucal_getHostTimeZone"));
  const auto ucal_getTimeZoneIDForWindowsIDRef = reinterpret_cast<ucal_getTimeZoneIDForWindowsID_func>(::GetProcAddress(icudll, "ucal_getTimeZoneIDForWindowsID"));

  // Note: ucal_getHostTimeZone might not be available on older Windows versions
  static auto ucal_getHostTimeZone_stub = [](UChar* result, int32_t resultCapacity, UErrorCode* ec) -> int32_t {
    if (ec) *ec = U_UNSUPPORTED_ERROR;
    return 0;
  };
  if (!ucal_getHostTimeZoneRef) {
    ucal_getHostTimeZoneRef = +ucal_getHostTimeZone_stub;
  }

  if (!ucal_closeRef || !ucal_getRef || !ucal_getCanonicalTimeZoneIDRef ||
      !ucal_getTimeZoneDisplayNameRef || !ucal_getTimeZoneTransitionDateRef ||
      !ucal_getTZDataVersionRef || !ucal_openRef ||
      !ucal_setMillisRef || !ucal_getMillisRef ||
      !ucal_getTimeZoneIDForWindowsIDRef) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }

  // Store the function pointers
  g_ucal_close.store(ucal_closeRef, std::memory_order_relaxed);
  g_ucal_get.store(ucal_getRef, std::memory_order_relaxed);
  g_ucal_getCanonicalTimeZoneID.store(ucal_getCanonicalTimeZoneIDRef,
                                      std::memory_order_relaxed);
  g_ucal_getTimeZoneDisplayName.store(ucal_getTimeZoneDisplayNameRef,
                                      std::memory_order_relaxed);
  g_ucal_getTimeZoneTransitionDate.store(ucal_getTimeZoneTransitionDateRef,
                                         std::memory_order_relaxed);
  g_ucal_getTZDataVersion.store(ucal_getTZDataVersionRef,
                                std::memory_order_relaxed);
  g_ucal_open.store(ucal_openRef, std::memory_order_relaxed);
  g_ucal_setMillis.store(ucal_setMillisRef, std::memory_order_relaxed);
  g_ucal_getMillis.store(ucal_getMillisRef, std::memory_order_relaxed);
  g_ucal_getHostTimeZone.store(ucal_getHostTimeZoneRef, std::memory_order_relaxed);
  g_ucal_getTimeZoneIDForWindowsID.store(ucal_getTimeZoneIDForWindowsIDRef, std::memory_order_relaxed);

  return {true, ucal_closeRef, ucal_getRef, ucal_getCanonicalTimeZoneIDRef,
          ucal_getTimeZoneDisplayNameRef, ucal_getTimeZoneTransitionDateRef,
          ucal_getTZDataVersionRef, ucal_openRef,
          ucal_setMillisRef, ucal_getMillisRef, ucal_getHostTimeZoneRef,
          ucal_getTimeZoneIDForWindowsIDRef};
}

// Helper to encode big-endian integers
void Encode32(char* dst, int32_t value) {
  dst[0] = static_cast<char>((value >> 24) & 0xff);
  dst[1] = static_cast<char>((value >> 16) & 0xff);
  dst[2] = static_cast<char>((value >> 8) & 0xff);
  dst[3] = static_cast<char>(value & 0xff);
}

void Encode64(char* dst, int64_t value) {
  dst[0] = static_cast<char>((value >> 56) & 0xff);
  dst[1] = static_cast<char>((value >> 48) & 0xff);
  dst[2] = static_cast<char>((value >> 40) & 0xff);
  dst[3] = static_cast<char>((value >> 32) & 0xff);
  dst[4] = static_cast<char>((value >> 24) & 0xff);
  dst[5] = static_cast<char>((value >> 16) & 0xff);
  dst[6] = static_cast<char>((value >> 8) & 0xff);
  dst[7] = static_cast<char>(value & 0xff);
}

// Structure to hold transition information
struct Transition {
  int64_t time;       // Unix timestamp
  int32_t offset;     // Seconds east of UTC
  bool is_dst;        // Is daylight saving time
  std::string abbr;   // Time zone abbreviation
};

// Structure to hold transition type
struct TransitionType {
  int32_t offset;     // Seconds east of UTC
  bool is_dst;        // Is daylight saving time
  uint8_t abbr_idx;   // Index into abbreviation string
};

// Get timezone abbreviation from ICU
std::string GetTimeZoneAbbr(const IcuFunctions& icu, UCalendar* cal,
                            bool is_dst) {
  UErrorCode status = U_ZERO_ERROR;
  const UCalendarDisplayNameType type =
      is_dst ? UCAL_SHORT_DST : UCAL_SHORT_STANDARD;

  int buffer_size = 16;
  std::unique_ptr<UChar[]> buffer = std::make_unique<UChar[]>(buffer_size);

  int length = icu.ucal_getTimeZoneDisplayName(
      cal, type, nullptr, buffer.get(), buffer_size, &status);
  if (status == U_BUFFER_OVERFLOW_ERROR && length > 0) {
    status = U_ZERO_ERROR;
    buffer_size = length + 1;
    buffer = std::make_unique<UChar[]>(buffer_size);
    length = icu.ucal_getTimeZoneDisplayName(
        cal, type, nullptr, buffer.get(), buffer_size, &status);
  }
  return FromUChars(buffer.get(), length);
}

// Collect transitions for a timezone using ICU
bool CollectTransitions(const IcuFunctions& icu, const std::string& name,
                       std::vector<Transition>& transitions) {
  auto zone_id = ToUChars(name);
  if (zone_id.second <= 0) {
    return false;
  }

  // Validate timezone name using ucal_getCanonicalTimeZoneID
  UErrorCode status = U_ZERO_ERROR;
  UBool is_system_id = false;
  int buffer_size = 256;
  std::unique_ptr<UChar[]> canonical_buffer = std::make_unique<UChar[]>(buffer_size);

  int32_t canonical_length = icu.ucal_getCanonicalTimeZoneID(
      zone_id.first.get(), zone_id.second, canonical_buffer.get(), buffer_size, 
      &is_system_id, &status);

  if (status == U_BUFFER_OVERFLOW_ERROR && canonical_length > 0) {
    status = U_ZERO_ERROR;
    buffer_size = canonical_length + 1;
    canonical_buffer = std::make_unique<UChar[]>(buffer_size);
    canonical_length = icu.ucal_getCanonicalTimeZoneID(
        zone_id.first.get(), zone_id.second, canonical_buffer.get(), buffer_size,
        &is_system_id, &status);
  }

  if (U_FAILURE(status) || canonical_length <= 0) {
    return false;  // Invalid timezone name
  }

  status = U_ZERO_ERROR;
  ScopedUCalendar cal(icu.ucal_open(zone_id.first.get(), zone_id.second,
                                    nullptr, UCAL_GREGORIAN, &status),
                     icu.ucal_close);
  if (U_FAILURE(status) || !cal) {
    return false;
  }

  icu.ucal_setMillis(cal.get(), std::numeric_limits<int64_t>::min() * 1000.0,
                     &status);
  if (U_FAILURE(status)) {
    return false;
  }
  const UDate min_time = icu.ucal_getMillis(cal.get(), &status);
  if (U_FAILURE(status)) {
    return false;
  }

  // Set initial time
  UDate current = static_cast<UDate>(min_time);
  icu.ucal_setMillis(cal.get(), current, &status);
  if (U_FAILURE(status)) {
    return false;
  }

  // Get initial state
  int32_t offset_millis = icu.ucal_get(cal.get(), UCAL_ZONE_OFFSET, &status);
  if (U_FAILURE(status)) return false;

  int32_t dst_millis = icu.ucal_get(cal.get(), UCAL_DST_OFFSET, &status);
  if (U_FAILURE(status)) return false;

  offset_millis += dst_millis;
  bool is_dst = dst_millis != 0;

  // Add initial transition
  Transition initial;
  initial.time = min_time;
  initial.offset = offset_millis / 1000;
  initial.is_dst = is_dst;
  initial.abbr = GetTimeZoneAbbr(icu, cal.get(), is_dst);
  transitions.push_back(initial);

  const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
  const UDate date_400y_later = 1000.0 * kSecsPer400Years + now;

  // Find all transitions
  while (current < date_400y_later) {
    UDate next_trans = 0;
    UBool has_trans = icu.ucal_getTimeZoneTransitionDate(
        cal.get(), UCAL_TZ_TRANSITION_NEXT, &next_trans, &status);

    if (!has_trans || U_FAILURE(status) || next_trans <= current) {
      break;
    }

    // Move to just after the transition
    icu.ucal_setMillis(cal.get(), next_trans, &status);
    if (U_FAILURE(status)) break;

    // Get new offset and DST status
    offset_millis = icu.ucal_get(cal.get(), UCAL_ZONE_OFFSET, &status);
    if (U_FAILURE(status)) break;

    dst_millis = icu.ucal_get(cal.get(), UCAL_DST_OFFSET, &status);
    if (U_FAILURE(status)) break;

    offset_millis += dst_millis;
    is_dst = dst_millis != 0;

    // Add transition
    Transition trans;
    trans.time = static_cast<int64_t>(next_trans / 1000.0);
    trans.offset = offset_millis / 1000;
    trans.is_dst = is_dst;
    trans.abbr = GetTimeZoneAbbr(icu, cal.get(), is_dst);
    transitions.push_back(trans);

    current = next_trans;
  }

  return !transitions.empty();
}

// A ZoneInfoSource implementation that generates TZDATA binary format
// on-the-fly using Windows ICU APIs. This allows CCTZ to work on Windows 10+
// without requiring bundled IANA timezone data files.
class IcuZoneInfoSource : public ZoneInfoSource {
 public:
  // ZoneInfoSource interface implementation
  std::size_t Read(void* ptr, std::size_t size) override;
  int Skip(std::size_t offset) override;
  std::string Version() const override;

  // Initialize with timezone name. Returns false on failure.
  bool Init(const std::string& name);

 private:
  IcuZoneInfoSource() = default;
  friend std::unique_ptr<ZoneInfoSource> cctz::CreateWinIcuZoneInfoSource(
      const std::string& name);

  // Generate TZDATA binary format from ICU data
  bool GenerateTzData(const std::string& name);

  // The generated TZDATA binary data
  std::vector<char> data_;

  // Current read position
  std::size_t pos_ = 0;

  // Version string (e.g., "2023a")
  std::string version_;
};

// Implementation of IcuZoneInfoSource methods
std::size_t IcuZoneInfoSource::Read(void* ptr, std::size_t size) {
  if (pos_ >= data_.size()) {
    return 0;  // EOF
  }

  const std::size_t available = data_.size() - pos_;
  const std::size_t to_read = std::min(size, available);

  if (to_read > 0) {
    std::memcpy(ptr, data_.data() + pos_, to_read);
    pos_ += to_read;
  }

  return to_read;
}

int IcuZoneInfoSource::Skip(std::size_t offset) {
  const std::size_t new_pos = pos_ + offset;
  if (new_pos > data_.size()) {
    return -1;  // Would go past EOF
  }
  pos_ = new_pos;
  return 0;
}

std::string IcuZoneInfoSource::Version() const {
  return version_;
}


bool IcuZoneInfoSource::Init(const std::string& name) {
  IcuFunctions icu = GetIcuFunctions();
  if (!icu.available) {
    return false;
  }

  // Get version
  UErrorCode status = U_ZERO_ERROR;
  const char* tz_version = icu.ucal_getTZDataVersion(&status);
  if (U_SUCCESS(status) && tz_version) {
    version_ = tz_version;
  }

  return GenerateTzData(name);
}

bool IcuZoneInfoSource::GenerateTzData(const std::string& name) {
  IcuFunctions icu = GetIcuFunctions();
  if (!icu.available) {
    return false;
  }

  // Collect transitions from ICU
  std::vector<Transition> transitions;
  if (!CollectTransitions(icu, name, transitions)) {
    return false;
  }

  // Build unique transition types and deduplicated abbreviations
  std::vector<TransitionType> types;
  std::map<std::pair<int32_t, bool>, uint8_t> type_map;
  std::string abbr_string;
  // Maps abbreviation to its index in abbr_string
  std::map<std::string, uint8_t> abbr_map;

  for (const auto& trans : transitions) {
    auto key = std::make_pair(trans.offset, trans.is_dst);
    if (type_map.find(key) == type_map.end()) {
      TransitionType type;
      type.offset = trans.offset;
      type.is_dst = trans.is_dst;

      // Check if abbreviation already exists
      auto abbr_it = abbr_map.find(trans.abbr);
      if (abbr_it != abbr_map.end()) {
        // Reuse existing abbreviation
        type.abbr_idx = abbr_it->second;
      } else {
        // Add new abbreviation
        type.abbr_idx = static_cast<uint8_t>(abbr_string.size());
        abbr_map[trans.abbr] = type.abbr_idx;
        abbr_string += trans.abbr;
        abbr_string += '\0';
      }

      type_map[key] = static_cast<uint8_t>(types.size());
      types.push_back(type);
    }
  }

  // Build TZDATA binary format
  data_.clear();

  // Version 2 format with both 32-bit and 64-bit sections
  const char kTzifMagic[] = "TZif";

  // For version 2, write 32-bit section first (for compatibility)
  // Limit transitions to those that fit in 32-bit time_t
  std::vector<Transition> trans32;
  for (const auto& trans : transitions) {
    if (trans.time >= std::numeric_limits<int32_t>::min() &&
        trans.time <= std::numeric_limits<int32_t>::max()) {
      trans32.push_back(trans);
    }
  }

  // === VERSION 1 SECTION (32-bit) ===
  // Reserve space for header
  data_.resize(sizeof(tzhead));

  // Fill first header with version 2
  tzhead* hdr1 = reinterpret_cast<tzhead*>(data_.data());
  std::memcpy(hdr1->tzh_magic, kTzifMagic, sizeof(hdr1->tzh_magic));
  hdr1->tzh_version[0] = '2';  // Version 2 as per RFC 8536
  std::memset(hdr1->tzh_reserved, 0, sizeof(hdr1->tzh_reserved));

  // Fill counts for 32-bit section
  Encode32(hdr1->tzh_ttisutcnt, 0);
  Encode32(hdr1->tzh_ttisstdcnt, 0);
  Encode32(hdr1->tzh_leapcnt, 0);
  Encode32(hdr1->tzh_timecnt, static_cast<int32_t>(trans32.size()));
  Encode32(hdr1->tzh_typecnt, static_cast<int32_t>(types.size()));
  Encode32(hdr1->tzh_charcnt, static_cast<int32_t>(abbr_string.size()));

  // Write 32-bit transition times
  for (const auto& trans : trans32) {
    char buf[4];
    Encode32(buf, static_cast<int32_t>(trans.time));
    data_.insert(data_.end(), buf, buf + 4);
  }

  // Write transition type indices
  for (const auto& trans : trans32) {
    auto key = std::make_pair(trans.offset, trans.is_dst);
    uint8_t type_idx = type_map[key];
    data_.push_back(type_idx);
  }

  // Write transition types
  for (const auto& type : types) {
    char buf[4];
    Encode32(buf, type.offset);
    data_.insert(data_.end(), buf, buf + 4);
    data_.push_back(type.is_dst ? 1 : 0);
    data_.push_back(type.abbr_idx);
  }

  // Write abbreviation string
  data_.insert(data_.end(), abbr_string.begin(), abbr_string.end());

  // No leap seconds, standard/wall indicators, or UTC/local indicators

  // === VERSION 2 SECTION (64-bit) ===
  // Second header
  std::size_t hdr2_pos = data_.size();
  data_.resize(data_.size() + sizeof(tzhead));
  tzhead* hdr2 = reinterpret_cast<tzhead*>(data_.data() + hdr2_pos);
  std::memcpy(hdr2->tzh_magic, kTzifMagic, sizeof(hdr2->tzh_magic));
  hdr2->tzh_version[0] = '2';  // Version 2
  std::memset(hdr2->tzh_reserved, 0, sizeof(hdr2->tzh_reserved));

  // Fill counts for 64-bit section
  Encode32(hdr2->tzh_ttisutcnt, 0);
  Encode32(hdr2->tzh_ttisstdcnt, 0);
  Encode32(hdr2->tzh_leapcnt, 0);
  Encode32(hdr2->tzh_timecnt, static_cast<int32_t>(transitions.size()));
  Encode32(hdr2->tzh_typecnt, static_cast<int32_t>(types.size()));
  Encode32(hdr2->tzh_charcnt, static_cast<int32_t>(abbr_string.size()));

  // Write 64-bit transition times
  for (const auto& trans : transitions) {
    char buf[8];
    Encode64(buf, trans.time);
    data_.insert(data_.end(), buf, buf + 8);
  }

  // Write transition type indices
  for (const auto& trans : transitions) {
    auto key = std::make_pair(trans.offset, trans.is_dst);
    uint8_t type_idx = type_map[key];
    data_.push_back(type_idx);
  }

  // Write transition types again
  for (const auto& type : types) {
    char buf[4];
    Encode32(buf, type.offset);
    data_.insert(data_.end(), buf, buf + 4);
    data_.push_back(type.is_dst ? 1 : 0);
    data_.push_back(type.abbr_idx);
  }

  // Write abbreviation string again
  data_.insert(data_.end(), abbr_string.begin(), abbr_string.end());

  // No leap seconds, standard/wall indicators, or UTC/local indicators

  // Add newline and empty POSIX spec (for version 2)
  data_.push_back('\n');
  data_.push_back('\n');

  // Reset read position
  pos_ = 0;

  return true;
}

}  // namespace

// Factory function implementation
std::unique_ptr<ZoneInfoSource> CreateWinIcuZoneInfoSource(
    const std::string& name) {
  auto source = std::unique_ptr<IcuZoneInfoSource>(new IcuZoneInfoSource());
  if (!source->Init(name)) {
    return nullptr;
  }
  return source;
}

std::string GetWinLocalTimeZone() {
  const auto icu_funcs = GetIcuFunctions();
  if (!icu_funcs.available) {
    return "";
  }

  // Try ucal_getHostTimeZone first (available on Windows 11+)
  UErrorCode status = U_ZERO_ERROR;
  int buffer_size = 256;
  std::unique_ptr<UChar[]> buffer = std::make_unique<UChar[]>(buffer_size);

  int32_t length = icu_funcs.ucal_getHostTimeZone(buffer.get(), buffer_size, &status);
  if (U_SUCCESS(status) && length > 0) {
    return FromUChars(buffer.get(), length);
  }

  // Fallback: Use Windows APIs + ICU mapping
  DYNAMIC_TIME_ZONE_INFORMATION info = {};
  if (::GetDynamicTimeZoneInformation(&info) == TIME_ZONE_ID_INVALID) {
    return "";
  }

  status = U_ZERO_ERROR;
  buffer_size = 256;
  buffer = std::make_unique<UChar[]>(buffer_size);

  length = icu_funcs.ucal_getTimeZoneIDForWindowsID(
      reinterpret_cast<const UChar*>(info.TimeZoneKeyName), -1, nullptr,
      buffer.get(), buffer_size, &status);
  if (status == U_BUFFER_OVERFLOW_ERROR && length > 0) {
    status = U_ZERO_ERROR;
    buffer_size = length + 1;
    buffer = std::make_unique<UChar[]>(buffer_size);
    length = icu_funcs.ucal_getTimeZoneIDForWindowsID(
        reinterpret_cast<const UChar*>(info.TimeZoneKeyName), -1, nullptr,
        buffer.get(), buffer_size, &status);
  }
  if (U_FAILURE(status) || length <= 0) {
    return "";
  }
  return FromUChars(buffer.get(), length);
}

}  // namespace cctz

#endif  // defined(_WIN32)

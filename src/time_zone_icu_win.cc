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

#if defined(_WIN32) && defined(CCTZ_USE_WIN_ICU)

#if !defined(NOMINMAX)
#define NOMINMAX
#endif  // !defined(NOMINMAX)
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cmath>
#include <deque>
#include <iterator>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "time_zone_if.h"

namespace cctz {
namespace {

const wchar_t kRegistryPath[] =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\";

struct REG_TZI_FORMAT {
  LONG Bias;
  LONG StandardBias;
  LONG DaylightBias;
  SYSTEMTIME StandardDate;
  SYSTEMTIME DaylightDate;
};

using UBool = uint8_t;
using UCalendar = void;
// originally UChar is char16_t, but wchar_t should also be fine on Windows.
using UChar = wchar_t;
using UDate = double;

enum UErrorCode : int32_t {
  U_ZERO_ERROR = 0,
  U_BUFFER_OVERFLOW_ERROR = 15,
  U_UNSUPPORTED_ERROR = 16,
};

constexpr bool U_SUCCESS(UErrorCode error) { return error <= U_ZERO_ERROR; }

constexpr bool U_FAILURE(UErrorCode error) { return error > U_ZERO_ERROR; }

int32_t __cdecl ucal_getHostTimeZone_stub(UChar* result, int32_t resultCapacity,
                                          UErrorCode* status) {
  if (status) {
    *status = U_UNSUPPORTED_ERROR;
  }
  return 0;
};

template <typename T>
static T AsProcAddress(HMODULE module, const char* name) {
  static_assert(
      std::is_pointer<T>::value &&
          std::is_function<typename std::remove_pointer<T>::type>::value,
      "T must be a function pointer type");
  const auto proc_address = ::GetProcAddress(module, name);
  return reinterpret_cast<T>(static_cast<void*>(proc_address));
}

struct IcuFunctions final {
  // ICU function signatures
  using ucal_getHostTimeZone_func = int32_t(__cdecl*)(UChar* result,
                                                      int32_t resultCapacity,
                                                      UErrorCode* status);
  using ucal_getTimeZoneIDForWindowsID_func =
      int32_t(__cdecl*)(const UChar* winid, int32_t len, const char* region,
                        UChar* id, int32_t idCapacity, UErrorCode* status);
  using ucal_getWindowsTimeZoneID_func =
      int32_t(__cdecl*)(const UChar* id, int32_t len, UChar* winid,
                        int32_t winidCapacity, UErrorCode* status);

  const bool available;
  const ucal_getHostTimeZone_func ucal_getHostTimeZone;
  const ucal_getTimeZoneIDForWindowsID_func ucal_getTimeZoneIDForWindowsID;
  const ucal_getWindowsTimeZoneID_func ucal_getWindowsTimeZoneID;

  static IcuFunctions Unavailable() {
    return {false, nullptr, nullptr, nullptr};
  }

  static IcuFunctions Get() {
    static std::atomic<bool> g_unavailable;
    if (g_unavailable.load(std::memory_order_relaxed)) {
      return IcuFunctions::Unavailable();
    }

    static std::atomic<ucal_getHostTimeZone_func> g_ucal_getHostTimeZone;
    static std::atomic<ucal_getTimeZoneIDForWindowsID_func>
        g_ucal_getTimeZoneIDForWindowsID;
    static std::atomic<ucal_getWindowsTimeZoneID_func>
        g_ucal_getWindowsTimeZoneID;

    // Check if already loaded
    {
      const auto ucal_getHostTimeZoneRef =
          g_ucal_getHostTimeZone.load(std::memory_order_relaxed);
      const auto ucal_getTimeZoneIDForWindowsIDRef =
          g_ucal_getTimeZoneIDForWindowsID.load(std::memory_order_relaxed);
      const auto ucal_getWindowsTimeZoneIDRef =
          g_ucal_getWindowsTimeZoneID.load(std::memory_order_relaxed);
      if (ucal_getHostTimeZoneRef != nullptr &&
          ucal_getTimeZoneIDForWindowsIDRef != nullptr &&
          ucal_getWindowsTimeZoneIDRef != nullptr) {
        return {true, ucal_getHostTimeZoneRef,
                ucal_getTimeZoneIDForWindowsIDRef,
                ucal_getWindowsTimeZoneIDRef};
      }
    }

    // Our goal here is to load the ICU DLL from the system directory, even when
    // the current process has loaded "icu.dll" from somewhere other than the
    // system directory. To do so we must use the full path here.
    std::wstring icu_dll_path;
    {
      const UINT size_with_null = ::GetSystemDirectoryW(nullptr, 0);
      icu_dll_path.reserve(size_with_null + 8);  // +8 for the "\\icu.dll" part
      icu_dll_path.resize(size_with_null);
      const UINT size_without_null =
          ::GetSystemDirectoryW(&icu_dll_path[0], size_with_null);
      if (size_without_null >= icu_dll_path.size()) {
        g_unavailable.store(true, std::memory_order_relaxed);
        return IcuFunctions::Unavailable();
      }
      icu_dll_path.resize(size_without_null);
      icu_dll_path.append(L"\\icu.dll");
    }
    // CAVEAT: LoadLibraryExW with LOAD_LIBRARY_SEARCH_SYSTEM32 is not
    // sufficient when "icu.dll" is already loaded from somewhere other than
    // the system directory. This is why we must pass a full path here.
    const HMODULE icu_dll = ::LoadLibraryW(icu_dll_path.c_str());
    if (icu_dll == nullptr) {
      g_unavailable.store(true, std::memory_order_relaxed);
      return IcuFunctions::Unavailable();
    }

    auto ucal_getHostTimeZoneRef = AsProcAddress<ucal_getHostTimeZone_func>(
        icu_dll, "ucal_getHostTimeZone");
    const auto ucal_getTimeZoneIDForWindowsIDRef =
        AsProcAddress<ucal_getTimeZoneIDForWindowsID_func>(
            icu_dll, "ucal_getTimeZoneIDForWindowsID");
    const auto ucal_getWindowsTimeZoneIDRef =
        AsProcAddress<ucal_getWindowsTimeZoneID_func>(
            icu_dll, "ucal_getWindowsTimeZoneID");

    if (!ucal_getHostTimeZoneRef) {
      // Note: ucal_getHostTimeZone can be unavailable on older Windows.
      ucal_getHostTimeZoneRef = ucal_getHostTimeZone_stub;
    }

    if (!ucal_getTimeZoneIDForWindowsIDRef || !ucal_getWindowsTimeZoneIDRef) {
      g_unavailable.store(true, std::memory_order_relaxed);
      return IcuFunctions::Unavailable();
    }

    // Store the function pointers
    g_ucal_getHostTimeZone.store(ucal_getHostTimeZoneRef,
                                 std::memory_order_relaxed);
    g_ucal_getTimeZoneIDForWindowsID.store(ucal_getTimeZoneIDForWindowsIDRef,
                                           std::memory_order_relaxed);
    g_ucal_getWindowsTimeZoneID.store(ucal_getWindowsTimeZoneIDRef,
                                      std::memory_order_relaxed);

    return {true, ucal_getHostTimeZoneRef, ucal_getTimeZoneIDForWindowsIDRef,
            ucal_getWindowsTimeZoneIDRef};
  }
};

// Convert UTF-8 string to std::wstring (UTF-16)
std::wstring Utf8ToUtf16(const std::string& utf8str) {
  if (utf8str.size() > std::numeric_limits<int>::max()) {
    return std::wstring();
  }
  const char* utf8str_ptr = utf8str.data();
  const int utf8str_len = static_cast<int>(utf8str.size());
  int num_counts = 0;
  {
    // Fast-path for small strings.
    const int buffer_size = 32;
    wchar_t buffer[buffer_size];
    num_counts =
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8str_ptr,
                              utf8str_len, buffer, buffer_size);
    if (num_counts <= buffer_size) {
      return std::wstring(buffer, num_counts);
    }
    if (num_counts > std::numeric_limits<int>::max()) {
      return std::wstring();
    }
  }

  auto ustr = std::unique_ptr<UChar[]>(new UChar[num_counts]);
  const int written_counts =
      ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8str_ptr,
                            utf8str_len, ustr.get(), num_counts);
  if (num_counts != written_counts) {
    return std::wstring();
  }
  return std::wstring(ustr.get(), num_counts);
}

// Convert wchar_t array (UTF-16) to UTF-8 string
std::string Utf16ToUtf8(const wchar_t* ptr, size_t size) {
  if (size > std::numeric_limits<int>::max()) {
    return std::string();
  }
  const int chars_len = static_cast<int>(size);
  int num_bytes_in_utf8 = 0;
  {
    const int buffer_size = 32;
    char buffer[buffer_size];
    num_bytes_in_utf8 =
        ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, ptr, chars_len,
                              buffer, buffer_size, nullptr, nullptr);
    if (num_bytes_in_utf8 <= buffer_size) {
      return std::string(buffer, num_bytes_in_utf8);
    }
  }
  auto buffer = std::unique_ptr<char[]>(new char[num_bytes_in_utf8]);
  const int num_written_bytes =
      ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, ptr, chars_len,
                            buffer.get(), num_bytes_in_utf8, nullptr, nullptr);
  if (num_written_bytes != num_bytes_in_utf8) {
    return std::string();
  }
  return std::string(buffer.get(), num_written_bytes);
}

WORD ToSystemTimeDayOfWeek(cctz::weekday wd) {
  switch (wd) {
    default:
    case cctz::weekday::sunday:
      return 0;
    case cctz::weekday::monday:
      return 1;
    case cctz::weekday::tuesday:
      return 2;
    case cctz::weekday::wednesday:
      return 3;
    case cctz::weekday::thursday:
      return 4;
    case cctz::weekday::friday:
      return 5;
    case cctz::weekday::saturday:
      return 6;
  }
}

cctz::weekday FromSystemTimeDayOfWeek(const SYSTEMTIME& system_time) {
  switch (system_time.wDayOfWeek) {
    default:
    case 0:
      return cctz::weekday::sunday;
    case 1:
      return cctz::weekday::monday;
    case 2:
      return cctz::weekday::tuesday;
    case 3:
      return cctz::weekday::wednesday;
    case 4:
      return cctz::weekday::thursday;
    case 5:
      return cctz::weekday::friday;
    case 6:
      return cctz::weekday::saturday;
  }
}

class TimeZoneInformationMap {
 public:
  TimeZoneInformationMap(const REG_TZI_FORMAT& base_info,
                         const std::vector<USHORT>& year_list,
                         const std::vector<REG_TZI_FORMAT>& info_list)
      : base_info_(base_info),
        year_list_(year_list),
        timezone_list_(info_list) {}

  const REG_TZI_FORMAT& Get(int32_t year) const {
    if (year_list_.empty()) {
      return base_info_;
    }
    const USHORT first_year = year_list_.front();
    if (year <= first_year) {
      // To be consistent with the Windows Time Zone API, use the first entry
      // for years before the first year in the list.
      return timezone_list_[0];
    }
    const USHORT last_year = year_list_.back();
    if (last_year < year) {
      return base_info_;
    }
    return timezone_list_[year - first_year];
  }

 private:
  REG_TZI_FORMAT base_info_;
  std::vector<USHORT> year_list_;
  std::vector<REG_TZI_FORMAT> timezone_list_;
};

bool GetDynamicTimeZoneInformation(const std::wstring& key_name,
                                   REG_TZI_FORMAT* base_info,
                                   std::vector<USHORT>* year_list_,
                                   std::vector<REG_TZI_FORMAT>* timezone_list) {
  if (key_name.empty() || key_name.size() > 128) {
    return false;
  }

  const std::wstring registry_path = std::wstring(kRegistryPath) + key_name;

  HKEY hkey = nullptr;
  if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, registry_path.c_str(), 0, KEY_READ,
                      &hkey) != ERROR_SUCCESS) {
    return false;
  }
  if (hkey == nullptr) {
    return false;
  }

  DWORD size = sizeof(REG_TZI_FORMAT);
  LSTATUS reg_result =
      ::RegGetValueW(hkey, nullptr, L"TZI", RRF_RT_REG_BINARY, nullptr,
                     reinterpret_cast<LPBYTE>(base_info), &size);
  if (reg_result != ERROR_SUCCESS || size != sizeof(REG_TZI_FORMAT)) {
    ::RegCloseKey(hkey);
    return false;
  }
  year_list_->clear();
  timezone_list->clear();

  HKEY hkey_dynamic_years = nullptr;
  reg_result =
      ::RegOpenKeyExW(hkey, L"Dynamic DST", 0, KEY_READ, &hkey_dynamic_years);
  ::RegCloseKey(hkey);
  if (reg_result != ERROR_SUCCESS || hkey_dynamic_years == nullptr) {
    return true;
  }

  DWORD first_year = 0;
  reg_result = ::RegGetValueW(hkey_dynamic_years, nullptr, L"FirstEntry",
                              RRF_RT_REG_DWORD, nullptr,
                              reinterpret_cast<LPBYTE>(&first_year), &size);
  if (reg_result != ERROR_SUCCESS) {
    ::RegCloseKey(hkey_dynamic_years);
    return false;
  }
  DWORD last_year = 0;
  reg_result = ::RegGetValueW(hkey_dynamic_years, nullptr, L"LastEntry",
                              RRF_RT_REG_DWORD, nullptr,
                              reinterpret_cast<LPBYTE>(&last_year), &size);
  if (reg_result != ERROR_SUCCESS) {
    ::RegCloseKey(hkey_dynamic_years);
    return false;
  }
  if (first_year > last_year) {
    ::RegCloseKey(hkey_dynamic_years);
    return false;
  }

  const size_t year_count = static_cast<size_t>(last_year - first_year + 1);
  year_list_->reserve(year_count);
  timezone_list->reserve(year_count);
  for (DWORD year = first_year; year <= last_year; ++year) {
    const std::wstring key = std::to_wstring(year);
    REG_TZI_FORMAT format;
    DWORD size = sizeof(REG_TZI_FORMAT);
    reg_result = ::RegGetValueW(hkey_dynamic_years, nullptr, key.c_str(),
                                RRF_RT_REG_BINARY, nullptr,
                                reinterpret_cast<LPBYTE>(&format), &size);
    if (reg_result != ERROR_SUCCESS || size != sizeof(REG_TZI_FORMAT)) {
      ::RegCloseKey(hkey_dynamic_years);
      return false;
    }
    year_list_->push_back(static_cast<USHORT>(year));
    timezone_list->push_back(format);
  }

  ::RegCloseKey(hkey_dynamic_years);
  return true;
}

std::wstring GetWindowsTimeZoneName(const IcuFunctions& icu,
                                    const std::wstring& iana_name) {
  if (iana_name.size() > std::numeric_limits<int32_t>::max()) {
    return std::wstring();
  }
  const int32_t iana_name_length = static_cast<int32_t>(iana_name.size());

  const int32_t buffer_size = 128;
  UChar buffer[buffer_size];
  UErrorCode status = U_ZERO_ERROR;
  const int32_t length = icu.ucal_getWindowsTimeZoneID(
      iana_name.c_str(), iana_name_length, buffer, buffer_size, &status);
  if (U_FAILURE(status) && length <= 0) {
    return std::wstring();
  }
  return std::wstring(buffer, length);
}

struct LocalTimeInfo {
  LocalTimeInfo() : offset_seconds(0), is_dst(false) {}
  civil_second civil_time;
  int32_t offset_seconds;
  bool is_dst;
};

struct TimeOffsetInfo {
  TimeOffsetInfo() : kind(time_zone::civil_lookup::UNIQUE) {}

  LocalTimeInfo from;
  LocalTimeInfo to;
  civil_second begin_cs;
  civil_second end_cs;
  time_point<seconds> tp;
  time_zone::civil_lookup::civil_kind kind;
};

bool ResolveSystemTime(const SYSTEMTIME& system_time, USHORT year,
                       civil_second* result) {
  if (system_time.wYear == year) {
    *result = civil_second(system_time.wYear, system_time.wMonth,
                           system_time.wDay, system_time.wHour,
                           system_time.wMinute, system_time.wSecond);
    return true;
  }
  if (system_time.wYear != 0) {
    return false;
  }

  const cctz::weekday target_weekday = FromSystemTimeDayOfWeek(system_time);
  cctz::civil_day target_day;
  if (system_time.wDay == 5) {
    // wDay == 5 means the last weekday of the month.
    int32_t tmp_year = year;
    int32_t tmp_month = system_time.wMonth + 1;
    if (tmp_month > 12) {
      tmp_month = 1;
      tmp_year += 1;
    }
    target_day =
        prev_weekday(cctz::civil_day(tmp_year, tmp_month, 1), target_weekday);
  } else {
    // Calcurate the first target weekday of the month.
    target_day = next_weekday(cctz::civil_day(year, system_time.wMonth, 1) - 1,
                              target_weekday);
    // Adjust the week number based on the wDay field.
    target_day += (system_time.wDay - 1) * 7;
  }

  civil_second cs(target_day.year(), target_day.month(), target_day.day(),
                  system_time.wHour, system_time.wMinute, system_time.wSecond);
  if (cs.hour() == 23 && cs.minute() == 59 && cs.second() == 59 &&
      system_time.wMilliseconds == 999) {
    cs += 1;
  }
  *result = cs;
  return true;
}

std::deque<TimeOffsetInfo> GetOffsetInfoInternal(
    const TimeZoneInformationMap& timezone_map, USHORT year) {
  const REG_TZI_FORMAT& year_info = timezone_map.Get(year);

  const civil_second year_begin(year, 1, 1, 0, 0, 0);

  bool has_std_begin = false;
  civil_second std_begin;
  if (year_info.StandardDate.wMonth != 0) {
    has_std_begin = ResolveSystemTime(year_info.StandardDate, year, &std_begin);
  }
  bool has_dst_begin = false;
  civil_second dst_begin;
  if (year_info.DaylightDate.wMonth != 0) {
    has_dst_begin = ResolveSystemTime(year_info.DaylightDate, year, &dst_begin);
  }

  const bool has_year_begin_transition =
      (has_std_begin && std_begin == year_begin) ||
      (has_dst_begin && dst_begin == year_begin);

  std::deque<TimeOffsetInfo> offsets;
  const auto dst_offset_seconds =
      -(year_info.Bias + year_info.DaylightBias) * 60;
  const auto std_offset_seconds =
      -(year_info.Bias + year_info.StandardBias) * 60;
  const auto dst_offset =
      -(year_info.DaylightBias - year_info.StandardBias) * 60;

  if (!has_year_begin_transition) {
    TimeOffsetInfo info = {};
    info.from.is_dst = false;
    info.from.offset_seconds = std_offset_seconds;
    info.from.civil_time = year_begin;
    info.to = info.from;
    info.tp = FromUnixSeconds(year_begin - std_offset_seconds -
                              civil_second(1970, 1, 1, 0, 0, 0));
    info.kind = time_zone::civil_lookup::UNIQUE;
    info.begin_cs = info.from.civil_time;
    info.end_cs = info.from.civil_time;
    offsets.push_back(info);
  }

  if (has_dst_begin) {
    TimeOffsetInfo info = {};
    if (dst_begin == year_begin) {
      info.kind = time_zone::civil_lookup::UNIQUE;
      info.from.is_dst = true;
      info.from.civil_time = year_begin;
      info.from.offset_seconds = dst_offset_seconds;
      info.to = info.from;
      info.tp = FromUnixSeconds(year_begin - dst_offset_seconds -
                                civil_second(1970, 1, 1, 0, 0, 0));
      info.begin_cs = info.from.civil_time;
      info.end_cs = info.from.civil_time;
    } else {
      info.kind = time_zone::civil_lookup::SKIPPED;
      info.from.is_dst = false;
      info.from.civil_time = dst_begin;
      info.from.offset_seconds = std_offset_seconds;
      info.to.is_dst = true;
      info.to.civil_time = (dst_begin + dst_offset);
      info.to.offset_seconds = dst_offset_seconds;
      info.tp = FromUnixSeconds(dst_begin - std_offset_seconds -
                                civil_second(1970, 1, 1, 0, 0, 0));
      info.begin_cs = info.from.civil_time;
      info.end_cs = info.to.civil_time;
    }
    offsets.push_back(info);
  }

  if (has_std_begin) {
    TimeOffsetInfo info = {};
    if (std_begin == year_begin) {
      info.kind = time_zone::civil_lookup::UNIQUE;
      info.from.is_dst = false;
      info.from.civil_time = year_begin;
      info.from.offset_seconds = std_offset_seconds;
      info.to = info.from;
      info.tp = FromUnixSeconds(year_begin - std_offset_seconds -
                                civil_second(1970, 1, 1, 0, 0, 0));
      info.begin_cs = info.from.civil_time;
      info.end_cs = info.from.civil_time;
    } else {
      info.kind = time_zone::civil_lookup::REPEATED;
      info.from.is_dst = true;
      info.from.civil_time = std_begin;
      info.from.offset_seconds = dst_offset_seconds;
      info.to.is_dst = false;
      info.to.civil_time = (std_begin - dst_offset);
      info.to.offset_seconds = std_offset_seconds;
      info.tp = FromUnixSeconds(std_begin - dst_offset_seconds -
                                civil_second(1970, 1, 1, 0, 0, 0));
      info.begin_cs = info.to.civil_time;
      info.end_cs = info.from.civil_time;
    }
    if (!has_dst_begin || dst_begin < std_begin) {
      offsets.push_back(info);
    } else {
      offsets.insert(offsets.end() - 1, info);
    }
  }

  return offsets;
}

std::deque<TimeOffsetInfo> GetOffsetInfo(
    const TimeZoneInformationMap& timezone_map, USHORT year_start,
    USHORT year_end) {
  std::deque<TimeOffsetInfo> offsets =
      GetOffsetInfoInternal(timezone_map, year_start);
  for (USHORT year = year_start + 1; year <= year_end; ++year) {
    auto next_offsets = GetOffsetInfoInternal(timezone_map, year);
    if (next_offsets.empty()) {
      continue;
    }
    auto next_front = next_offsets.front();
    const auto& back = offsets.back();
    if (next_front.kind == time_zone::civil_lookup::UNIQUE &&
        next_front.from.offset_seconds == back.to.offset_seconds) {
      next_offsets.pop_front();
      if (next_front.from.is_dst != back.to.is_dst) {
        next_front.from.is_dst = back.to.is_dst;
        offsets.push_back(next_front);
      }
    }
    for (const auto& next_offset : next_offsets) {
      offsets.push_back(next_offset);
    }
  }
  return offsets;
}

class TimeZoneIcuWin final : public TimeZoneIf {
 public:
  TimeZoneIcuWin(const REG_TZI_FORMAT& base_info,
                 const std::vector<USHORT>& year_list,
                 const std::vector<REG_TZI_FORMAT>& info_list)
      : timezone_map_(base_info, year_list, info_list) {}

  TimeZoneIcuWin(const TimeZoneIcuWin&) = delete;
  TimeZoneIcuWin(TimeZoneIcuWin&&) = delete;
  TimeZoneIcuWin& operator=(const TimeZoneIcuWin&) = delete;

  static std::unique_ptr<TimeZoneIf> Create(const std::string& name) {
    const auto icu = IcuFunctions::Get();
    if (!icu.available) {
      return nullptr;
    }
    const std::wstring wide_name = Utf8ToUtf16(name);
    const std::wstring win_timezone_name =
        GetWindowsTimeZoneName(icu, wide_name);
    if (win_timezone_name.empty()) {
      return nullptr;
    }

    REG_TZI_FORMAT base_info;
    std::vector<USHORT> year_list;
    std::vector<REG_TZI_FORMAT> info_list;

    if (!GetDynamicTimeZoneInformation(win_timezone_name, &base_info,
                                       &year_list, &info_list)) {
      return nullptr;
    }
    return std::unique_ptr<TimeZoneIcuWin>(
        new TimeZoneIcuWin(base_info, year_list, info_list));
  }

  // TimeZoneIf implementations.
  time_zone::absolute_lookup BreakTime(
      const time_point<seconds>& tp) const override {
    const auto utc =
        cctz::civil_second(1970, 1, 1, 0, 0, 0) + cctz::ToUnixSeconds(tp);
    const USHORT utc_year = static_cast<USHORT>(utc.year());
    const auto offsets =
        GetOffsetInfo(timezone_map_, utc_year - 1, utc_year + 1);
    if (offsets.empty()) {
      return {};
    }

    size_t prev_index = 0;
    if (offsets.size() > 1) {
      for (size_t i = 1; i < offsets.size(); ++i) {
        const auto& prev = offsets[i - 1];
        const auto& next = offsets[i];
        if (prev.tp <= tp && tp < next.tp) {
          prev_index = i - 1;
          break;
        }
      }
    }
    const auto& to_info = offsets[prev_index].to;
    time_zone::absolute_lookup result;
    result.cs = utc + to_info.offset_seconds;
    result.offset = to_info.offset_seconds;
    result.is_dst = to_info.is_dst;
    // TODO: Use FixedOffsetToAbbr
    result.abbr = "";
    return result;
  }

  time_zone::civil_lookup MakeTime(const civil_second& cs) const override {
    const USHORT year = static_cast<USHORT>(cs.year());
    const auto& offsets = GetOffsetInfo(timezone_map_, year - 1, year + 1);
    if (offsets.empty()) {
      return {};
    }

    if (offsets.size() == 1 &&
        offsets.front().kind == time_zone::civil_lookup::UNIQUE) {
      time_zone::civil_lookup result;
      result.kind = time_zone::civil_lookup::UNIQUE;
      result.pre = FromUnixSeconds(cs - offsets.front().from.offset_seconds -
                                   civil_second(1970, 1, 1, 0, 0, 0));
      result.post = result.pre;
      result.trans = result.pre;
      return result;
    }

    for (size_t i = 0; i < offsets.size(); ++i) {
      const auto& offset = offsets[i];
      if (offset.begin_cs <= cs && cs < offset.end_cs) {
        time_zone::civil_lookup result;
        result.kind = offset.kind;
        result.pre = FromUnixSeconds(cs - offset.from.offset_seconds -
                                     civil_second(1970, 1, 1, 0, 0, 0));
        result.post = FromUnixSeconds(cs - offset.to.offset_seconds -
                                      civil_second(1970, 1, 1, 0, 0, 0));
        result.trans = offset.tp;
        return result;
      }
      if ((i + 1) < offsets.size()) {
        const auto& next = offsets[i + 1];
        if (offset.end_cs <= cs && cs < next.begin_cs) {
          time_zone::civil_lookup result;
          result.kind = time_zone::civil_lookup::UNIQUE;
          result.pre = FromUnixSeconds(cs - offset.to.offset_seconds -
                                       civil_second(1970, 1, 1, 0, 0, 0));
          result.post = result.pre;
          result.trans = result.pre;
          return result;
        }
      }
    }
    return {};
  }

  bool NextTransition(const time_point<seconds>& tp,
                      time_zone::civil_transition* trans) const override {
    const auto sec = std::chrono::time_point_cast<seconds>(
                         std::chrono::system_clock::now()) -
                     tp;
    if (sec > seconds(60 * 60 * 24 * 365 * 10)) {
      return false;  // Stop if more than roughly 10 years in the future.
    }

    const auto utc =
        cctz::civil_second(1970, 1, 1, 0, 0, 0) + cctz::ToUnixSeconds(tp);

    USHORT utc_year = 1970;
    if (utc.year() > std::numeric_limits<USHORT>::max()) {
      return false;
    }
    if (utc.year() > utc_year) {
      utc_year = static_cast<USHORT>(utc.year());
    }
    const auto& offsets = GetOffsetInfo(timezone_map_, utc_year, utc_year + 1);
    if (offsets.empty()) {
      return false;
    }
    for (size_t i = 0; i < offsets.size(); ++i) {
      const auto& offset = offsets[i];
      if (tp < offset.tp) {
        if (offset.kind != time_zone::civil_lookup::UNIQUE) {
          trans->from = offset.from.civil_time;
          trans->to = offset.to.civil_time;
          return true;
        }
        return false;
      }
    }
    return false;
  }

  bool PrevTransition(const time_point<seconds>& tp,
                      time_zone::civil_transition* trans) const override {
    const auto utc =
        cctz::civil_second(1970, 1, 1, 0, 0, 0) + cctz::ToUnixSeconds(tp);
    if (utc.year() < 1970) {
      return false;
    }
    USHORT utc_year = 0;
    utc_year = static_cast<USHORT>(utc.year());

    const auto& offsets =
        GetOffsetInfo(timezone_map_, utc_year - 1, utc_year + 1);
    if (offsets.empty()) {
      return false;
    }
    for (size_t i = offsets.size(); i > 0; --i) {
      const auto& offset = offsets[i - 1];
      if (offset.tp < tp) {
        if (offset.kind != time_zone::civil_lookup::UNIQUE) {
          trans->from = offset.from.civil_time;
          trans->to = offset.to.civil_time;
          return true;
        }
        return false;
      }
    }
    return false;
  }

  std::string Version() const override { return std::string(); }

  std::string Description() const override { return std::string(); }

 private:
  TimeZoneInformationMap timezone_map_;
};

}  // namespace

std::string GetWinLocalTimeZone() {
  const auto icu = IcuFunctions::Get();
  if (!icu.available) {
    return std::string();
  }

  int32_t length = 0;

  // Try ucal_getHostTimeZone first (available on Windows 11+)
  UErrorCode status = U_ZERO_ERROR;
  {
    const int buffer_size = 32;
    UChar buffer[buffer_size];
    length = icu.ucal_getHostTimeZone(buffer, buffer_size, &status);
    if (U_SUCCESS(status) && length >= 0) {
      return Utf16ToUtf8(buffer, length);
    }
  }
  if (status == U_BUFFER_OVERFLOW_ERROR && length > 0) {
    const int buffer_size = length + 1;  // +1 for null terminator
    auto buffer = std::unique_ptr<UChar[]>(new UChar[buffer_size]);
    status = U_ZERO_ERROR;
    length = icu.ucal_getHostTimeZone(buffer.get(), buffer_size, &status);
    if (U_SUCCESS(status) && length >= 0) {
      return Utf16ToUtf8(buffer.get(), length);
    }
  }

  // Fallback: Use Windows APIs + ICU mapping
  DYNAMIC_TIME_ZONE_INFORMATION info = {};
  if (::GetDynamicTimeZoneInformation(&info) == TIME_ZONE_ID_INVALID) {
    return std::string();
  }
  {
    const int buffer_size = 32;
    UChar buffer[buffer_size];
    status = U_ZERO_ERROR;
    length = icu.ucal_getTimeZoneIDForWindowsID(
        info.TimeZoneKeyName, -1, nullptr, buffer, buffer_size, &status);
    if (U_SUCCESS(status) && length >= 0) {
      return Utf16ToUtf8(buffer, length);
    }
    if (status != U_BUFFER_OVERFLOW_ERROR || length <= 0) {
      return std::string();
    }
  }
  const int buffer_size = length + 1;  // +1 for null terminator
  auto buffer = std::unique_ptr<UChar[]>(new UChar[buffer_size]);
  status = U_ZERO_ERROR;
  length = icu.ucal_getTimeZoneIDForWindowsID(
      info.TimeZoneKeyName, -1, nullptr, buffer.get(), buffer_size, &status);
  if (U_SUCCESS(status) && length >= 0) {
    return Utf16ToUtf8(buffer.get(), length);
  }
  return std::string();
}

std::unique_ptr<TimeZoneIf> MakeWin32TimeZone(const std::string& name) {
  return TimeZoneIcuWin::Create(name);
}

}  // namespace cctz

#else

namespace cctz {

std::string GetWinLocalTimeZone() { return std::string(); }

std::unique_ptr<TimeZoneIf> MakeWin32TimeZone(const std::string& name) {
  return nullptr;
}

}  // namespace cctz

#endif

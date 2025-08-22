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

#include "time_zone_win.h"

#if defined(_WIN32)

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

#include "time_zone_fixed.h"
#include "time_zone_if.h"

// Disable constexpr support unless we are in C++14 mode.
#if __cpp_constexpr >= 201304 || (defined(_MSC_VER) && _MSC_VER >= 1910)
#define CONSTEXPR_F constexpr  // function
#else
#define CONSTEXPR_F inline
#endif

#if defined(__cpp_lib_chrono) && __cpp_lib_chrono >= 201907L
#define CONSTEXPR_CHRONO_F constexpr
#else
#define CONSTEXPR_CHRONO_F inline
#endif

namespace cctz {
namespace {

// originally UChar is defined as char16_t in ICU, but it is also safe to assume
// wchar_t and char16_t are equivalent on Windows.
using UChar = wchar_t;

enum UErrorCode : int32_t {
  U_ZERO_ERROR = 0,
  U_BUFFER_OVERFLOW_ERROR = 15,
  U_UNSUPPORTED_ERROR = 16,
};

CONSTEXPR_F bool U_SUCCESS(UErrorCode error) { return error <= U_ZERO_ERROR; }

CONSTEXPR_F bool U_FAILURE(UErrorCode error) { return error > U_ZERO_ERROR; }

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

const wchar_t kRegistryPath[] =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones";

struct REG_TZI_FORMAT {
  LONG Bias;
  LONG StandardBias;
  LONG DaylightBias;
  SYSTEMTIME StandardDate;
  SYSTEMTIME DaylightDate;
};

CONSTEXPR_F
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

CONSTEXPR_F
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

CONSTEXPR_CHRONO_F
civil_second
TpToUtc(const time_point<seconds>& tp) {
  return civil_second(1970, 1, 1, 0, 0, 0) +
         (tp - std::chrono::time_point_cast<seconds>(
                   std::chrono::system_clock::from_time_t(0)))
             .count();
}

CONSTEXPR_CHRONO_F
time_point<seconds>
UtcToTp(const civil_second& cs) {
  return std::chrono::time_point_cast<seconds>(
             std::chrono::system_clock::from_time_t(0)) +
         seconds(cs - civil_second(1970, 1, 1, 0, 0, 0));
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
                                   std::vector<REG_TZI_FORMAT>* timezone_list,
                                   DWORD* tz_version) {
  if (key_name.empty() || key_name.size() > 128) {
    return false;
  }

  HKEY hkey_timezone_root = nullptr;
  if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegistryPath, 0, KEY_READ,
                      &hkey_timezone_root) != ERROR_SUCCESS) {
    return false;
  }
  if (hkey_timezone_root == nullptr) {
    return false;
  }
  DWORD timezone_version = 0;
  DWORD size = sizeof(timezone_version);
  if (::RegGetValueW(hkey_timezone_root, nullptr, L"TzVersion",
                     RRF_RT_REG_DWORD, nullptr,
                     reinterpret_cast<LPBYTE>(&timezone_version),
                     &size) == ERROR_SUCCESS) {
    if (tz_version != nullptr) {
      *tz_version = timezone_version;
    }
  }

  HKEY hkey_timezone = nullptr;
  if (::RegOpenKeyExW(hkey_timezone_root, key_name.c_str(), 0, KEY_READ,
                      &hkey_timezone) != ERROR_SUCCESS) {
    return false;
  }
  ::RegCloseKey(hkey_timezone_root);
  if (hkey_timezone == nullptr) {
    return false;
  }

  size = sizeof(REG_TZI_FORMAT);
  LSTATUS reg_result =
      ::RegGetValueW(hkey_timezone, nullptr, L"TZI", RRF_RT_REG_BINARY, nullptr,
                     reinterpret_cast<LPBYTE>(base_info), &size);
  if (reg_result != ERROR_SUCCESS || size != sizeof(REG_TZI_FORMAT)) {
    ::RegCloseKey(hkey_timezone);
    return false;
  }
  year_list_->clear();
  timezone_list->clear();

  HKEY hkey_dynamic_years = nullptr;
  reg_result = ::RegOpenKeyExW(hkey_timezone, L"Dynamic DST", 0, KEY_READ,
                               &hkey_dynamic_years);
  ::RegCloseKey(hkey_timezone);
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

struct TimeZoneBaseInfo {
  TimeZoneBaseInfo() : offset_seconds(0), dst(false) {}
  int32_t offset_seconds;
  bool dst;
};

struct RegistryTimezoneInfo {
  RegistryTimezoneInfo() {}
  civil_second from_civil_time;
  TimeZoneBaseInfo to;
};

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
  time_point<seconds> tp;
  time_zone::civil_lookup::civil_kind kind;

  const civil_second& earlier_cs() const {
    // Equivalent to std::min(from.civil_time, to.civil_time)
    return kind == time_zone::civil_lookup::REPEATED ? to.civil_time
                                                     : from.civil_time;
  }
  const civil_second& later_cs() const {
    // Equivalent to std::max(from.civil_time, to.civil_time)
    return kind == time_zone::civil_lookup::REPEATED ? from.civil_time
                                                     : to.civil_time;
  }
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

std::deque<RegistryTimezoneInfo> ParseTimeZoneInfo(const REG_TZI_FORMAT& format,
                                                   USHORT year) {
  const civil_second year_begin(year, 1, 1, 0, 0, 0);
  bool has_std_begin = false;
  civil_second std_begin;
  if (format.StandardDate.wMonth != 0) {
    has_std_begin = ResolveSystemTime(format.StandardDate, year, &std_begin);
  }
  bool has_dst_begin = false;
  civil_second dst_begin;
  if (format.DaylightDate.wMonth != 0) {
    has_dst_begin = ResolveSystemTime(format.DaylightDate, year, &dst_begin);
  }

  std::deque<RegistryTimezoneInfo> result;
  if (!(has_std_begin && std_begin == year_begin) &&
      !(has_dst_begin && dst_begin == year_begin)) {
    RegistryTimezoneInfo info;
    info.from_civil_time = year_begin;
    info.to.offset_seconds = -format.Bias * 60;
    info.to.dst = false;
    result.push_back(info);
  }
  if (has_std_begin) {
    RegistryTimezoneInfo info;
    info.from_civil_time = std_begin;
    info.to.offset_seconds = -(format.Bias + format.StandardBias) * 60;
    info.to.dst = false;
    result.push_back(info);
  }
  if (has_dst_begin) {
    RegistryTimezoneInfo info;
    info.from_civil_time = dst_begin;
    info.to.offset_seconds = -(format.Bias + format.DaylightBias) * 60;
    info.to.dst = true;
    if (has_std_begin) {
      if (dst_begin < std_begin) {
        result.insert(result.end() - 1, info);
      } else if (dst_begin == std_begin) {
        result.pop_back();
        result.push_back(info);
      } else {
        result.push_back(info);
      }
    } else {
      result.push_back(info);
    }
  }

  return result;
}

std::deque<TimeOffsetInfo> GetOffsetInfo(
    const TimeZoneInformationMap& timezone_map, USHORT year_start,
    USHORT year_end) {
  std::deque<TimeOffsetInfo> result;
  TimeZoneBaseInfo last_base_info;
  for (USHORT year = year_start - 1; year <= year_end; ++year) {
    const auto transitions = ParseTimeZoneInfo(timezone_map.Get(year), year);
    if (year == year_start - 1) {
      last_base_info = transitions.back().to;
      continue;
    }
    for (const auto& transition : transitions) {
      TimeOffsetInfo info;
      info.from.civil_time = transition.from_civil_time;
      info.from.offset_seconds = last_base_info.offset_seconds;
      info.from.is_dst = last_base_info.dst;
      info.tp =
          UtcToTp(transition.from_civil_time - last_base_info.offset_seconds);
      info.to.offset_seconds = transition.to.offset_seconds;
      info.to.is_dst = transition.to.dst;
      const int32_t offset_diff =
          transition.to.offset_seconds - last_base_info.offset_seconds;
      info.to.civil_time = info.from.civil_time + offset_diff;
      if (offset_diff > 0) {
        info.kind = time_zone::civil_lookup::SKIPPED;
      } else if (offset_diff == 0) {
        if (!result.empty()) {
          const auto& last_info = result.back();
          if (last_info.to.offset_seconds == info.from.offset_seconds &&
              last_info.to.is_dst == info.from.is_dst) {
            // Redundant entry.
            continue;
          }
        }
        info.kind = time_zone::civil_lookup::UNIQUE;
      } else {
        info.kind = time_zone::civil_lookup::REPEATED;
      }
      if (!result.empty()) {
        const auto& last_info = result.back();
        if (last_info.kind == info.kind &&
            last_info.from.civil_time == info.from.civil_time &&
            last_info.from.offset_seconds == info.from.offset_seconds &&
            last_info.from.is_dst == info.from.is_dst &&
            last_info.to.civil_time == info.to.civil_time &&
            last_info.to.offset_seconds == info.to.offset_seconds &&
            last_info.to.is_dst == info.to.is_dst && last_info.tp == info.tp) {
          // Redundant entry.
          continue;
        }
      }
      result.push_back(info);
      last_base_info = transition.to;
    }
  }
  // Remove redundant UNIQUE entries at the beginning.
  while (!result.empty()) {
    const auto& front = result.front();
    if (front.kind != time_zone::civil_lookup::UNIQUE) {
      break;
    }
    result.pop_front();
  }
  return result;
}

const char* kCommonAbbrs[] = {
    "GMT-14", "GMT-13:30", "GMT-13", "GMT-12:30", "GMT-12", "GMT-11:30",
    "GMT-11", "GMT-10:30", "GMT-10", "GMT-09:30", "GMT-09", "GMT-08:30",
    "GMT-08", "GMT-07:30", "GMT-07", "GMT-06:30", "GMT-06", "GMT-05:30",
    "GMT-05", "GMT-04:30", "GMT-04", "GMT-03:30", "GMT-03", "GMT-02:30",
    "GMT-02", "GMT-01:30", "GMT-01", "GMT+00:30", "GMT",    "GMT+00:30",
    "GMT+01", "GMT+01:30", "GMT+02", "GMT+02:30", "GMT+03", "GMT+03:30",
    "GMT+04", "GMT+04:30", "GMT+05", "GMT+05:30", "GMT+06", "GMT+06:30",
    "GMT+07", "GMT+07:30", "GMT+08", "GMT+08:30", "GMT+09", "GMT+09:30",
    "GMT+10", "GMT+10:30", "GMT+11", "GMT+11:30", "GMT+12", "GMT+12:30",
    "GMT+13", "GMT+13:30", "GMT+14",
};

CONSTEXPR_F
const char* GetCommonAbbreviation(int32_t offset_seconds) {
  if (offset_seconds % 1800 == 0) {
    const int32_t halfhour_offset = offset_seconds / 1800;
    if (-28 <= halfhour_offset && halfhour_offset <= 28) {
      return kCommonAbbrs[halfhour_offset + 28];
    }
  }
  return nullptr;
}

class AbbreviationMap {
 public:
  AbbreviationMap(std::vector<int32_t> index_key,
                  std::vector<size_t> index_value, std::string abbr_buffer)
      : index_key_(std::move(index_key)),
        index_value_(std::move(index_value)),
        abbr_buffer_(std::move(abbr_buffer)) {}

  const char* GetAbbr(int32_t offset_seconds) const {
    const char* common_abbr = GetCommonAbbreviation(offset_seconds);
    if (common_abbr != nullptr) {
      return common_abbr;
    }
    for (size_t i = 0; i < index_key_.size(); ++i) {
      if (index_key_[i] == offset_seconds) {
        return abbr_buffer_.c_str() + index_value_[i];
      }
    }
    return "";
  }

 private:
  const std::vector<int32_t> index_key_;
  const std::vector<size_t> index_value_;
  const std::string abbr_buffer_;
};

class AbbreviationMapSource {
 public:
  AbbreviationMapSource() = default;
  void Add(int32_t offset_seconds, const std::string& abbr) {
    index_key_.push_back(offset_seconds);
    index_value_.push_back(abbr_buffer_.size());
    abbr_buffer_.append(abbr);
  }

  AbbreviationMap MoveToMap() {
    index_key_.shrink_to_fit();
    index_value_.shrink_to_fit();
    abbr_buffer_.shrink_to_fit();
    return AbbreviationMap(std::move(index_key_), std::move(index_value_),
                           std::move(abbr_buffer_));
  }

  void Add(const REG_TZI_FORMAT& info) {
    AddInternal(-info.Bias * 60);
    if (info.StandardBias != 0) {
      AddInternal(-(info.Bias + info.StandardBias) * 60);
    }
    if (info.DaylightBias != 0) {
      AddInternal(-(info.Bias + info.DaylightBias) * 60);
    }
  }

 private:
  void AddInternal(int32_t offset_seconds) {
    if (GetCommonAbbreviation(offset_seconds) != nullptr) {
      return;  // Already exists as a common abbreviation.
    }
    for (size_t i = 0; i < index_key_.size(); ++i) {
      if (index_key_[i] == offset_seconds) {
        return;  // Already exists.
      }
    }
    index_key_.push_back(offset_seconds);
    if (!abbr_buffer_.empty()) {
      abbr_buffer_ += '\0';
    }
    const size_t index = abbr_buffer_.size();
    index_value_.push_back(index);
    abbr_buffer_.append("GMT");
    abbr_buffer_.append(cctz::FixedOffsetToAbbr(cctz::seconds(offset_seconds)));
  }
  std::vector<int32_t> index_key_;
  std::vector<size_t> index_value_;
  std::string abbr_buffer_;
};

class TimeZoneIcuWin final : public TimeZoneIf {
 public:
  TimeZoneIcuWin(const REG_TZI_FORMAT& base_info,
                 const std::vector<USHORT>& year_list,
                 const std::vector<REG_TZI_FORMAT>& info_list,
                 AbbreviationMap abbr_map,
                 std::deque<TimeOffsetInfo> transitions, bool starts_with_fixed,
                 bool ends_with_fixed)
      : timezone_map_(base_info, year_list, info_list),
        transitions_(std::move(transitions)),
        abbr_map_(std::move(abbr_map)),
        starts_with_fixed_(starts_with_fixed),
        ends_with_fixed_(ends_with_fixed) {}

  TimeZoneIcuWin(const TimeZoneIcuWin&) = delete;
  TimeZoneIcuWin(TimeZoneIcuWin&&) = delete;
  TimeZoneIcuWin& operator=(const TimeZoneIcuWin&) = delete;

  // TimeZoneIf implementations.
  time_zone::absolute_lookup BreakTime(
      const time_point<seconds>& tp) const override {
    const bool cached =
        (transitions_.front().tp <= tp && tp <= transitions_.back().tp) ||
        (starts_with_fixed_ && tp < transitions_.front().tp) ||
        (ends_with_fixed_ && transitions_.back().tp < tp);
    const auto utc = TpToUtc(tp);
    const USHORT utc_year = static_cast<USHORT>(utc.year());
    const std::deque<TimeOffsetInfo>& offsets =
        cached ? transitions_
               : GetOffsetInfo(timezone_map_, utc_year - 1, utc_year + 1);
    if (offsets.empty()) {
      return {};
    }
    const LocalTimeInfo* info = nullptr;
    {
      if (tp < offsets.front().tp) {
        info = &offsets.front().from;
      } else {
        for (size_t i = 1; i < offsets.size(); ++i) {
          if (offsets[i - 1].tp <= tp && tp < offsets[i].tp) {
            info = &offsets[i - 1].to;
            break;
          }
        }
      }
      if (info == nullptr) {
        info = &offsets.back().to;
      }
    }
    const int32_t offset_seconds = info->offset_seconds;
    time_zone::absolute_lookup result;
    result.cs = utc + offset_seconds;
    result.offset = offset_seconds;
    result.is_dst = info->is_dst;
    result.abbr = abbr_map_.GetAbbr(offset_seconds);
    return result;
  }

  time_zone::civil_lookup MakeTime(const civil_second& cs) const override {
    const bool cached =
        (transitions_.front().earlier_cs() <= cs &&
         cs <= transitions_.back().later_cs()) ||
        (starts_with_fixed_ && cs < transitions_.front().earlier_cs()) ||
        (ends_with_fixed_ && transitions_.back().later_cs() < cs);

    const USHORT year = static_cast<USHORT>(cs.year());
    const auto& offsets =
        cached ? transitions_
               : GetOffsetInfo(timezone_map_, year - 1, year + 1);
    if (offsets.empty()) {
      return {};
    }

    if (cs < offsets.front().earlier_cs()) {
      time_zone::civil_lookup result;
      result.kind = time_zone::civil_lookup::UNIQUE;
      result.pre = UtcToTp(cs - offsets.front().from.offset_seconds);
      result.post = result.pre;
      result.trans = result.pre;
      return result;
    }

    for (size_t i = 0; i < offsets.size(); ++i) {
      const auto& offset = offsets[i];
      if (offset.earlier_cs() <= cs && cs < offset.later_cs()) {
        time_zone::civil_lookup result;
        result.kind = offset.kind;
        result.pre = UtcToTp(cs - offset.from.offset_seconds);
        result.post = UtcToTp(cs - offset.to.offset_seconds);
        result.trans = offset.tp;
        return result;
      }
      if ((i + 1) < offsets.size()) {
        const auto& next = offsets[i + 1];
        if (offset.later_cs() <= cs && cs < next.earlier_cs()) {
          time_zone::civil_lookup result;
          result.kind = time_zone::civil_lookup::UNIQUE;
          result.pre = UtcToTp(cs - offset.to.offset_seconds);
          result.post = result.pre;
          result.trans = result.pre;
          return result;
        }
      }
    }

    time_zone::civil_lookup result;
    result.kind = time_zone::civil_lookup::UNIQUE;
    result.pre = UtcToTp(cs - offsets.back().to.offset_seconds);
    result.post = result.pre;
    result.trans = result.pre;
    return result;
  }

  bool NextTransition(const time_point<seconds>& tp,
                      time_zone::civil_transition* trans) const override {
    if (transitions_.empty()) {
      return false;
    }
    const auto it = std::upper_bound(
        transitions_.begin(), transitions_.end(), tp,
        [](const time_point<seconds>& value, const TimeOffsetInfo& info) {
          return value < info.tp;
        });
    if (it == transitions_.end()) {
      return false;
    }
    trans->from = it->from.civil_time;
    trans->to = it->to.civil_time;
    return true;
  }

  bool PrevTransition(const time_point<seconds>& tp,
                      time_zone::civil_transition* trans) const override {
    if (transitions_.empty()) {
      return false;
    }
    auto it = std::lower_bound(
        transitions_.begin(), transitions_.end(), tp,
        [](const TimeOffsetInfo& info, const time_point<seconds>& value) {
          return info.tp < value;
        });
    if (it == transitions_.begin()) {
      return false;
    }
    --it;
    trans->from = it->from.civil_time;
    trans->to = it->to.civil_time;
    return true;
  }

  std::string Version() const override { return std::string(); }

  std::string Description() const override { return std::string(); }

 private:
  const TimeZoneInformationMap timezone_map_;
  const std::deque<TimeOffsetInfo> transitions_;
  const AbbreviationMap abbr_map_;
  const bool starts_with_fixed_;
  const bool ends_with_fixed_;
};

class FixedTimeZone final : public TimeZoneIf {
 public:
  explicit FixedTimeZone(int32_t offset_sec, std::string desc)
      : offset_sec_(offset_sec),
        abbr_("GMT" + cctz::FixedOffsetToAbbr(cctz::seconds(offset_sec))),
        desc_(std::move(desc)) {}

  FixedTimeZone(const FixedTimeZone&) = delete;
  FixedTimeZone(FixedTimeZone&&) = delete;
  FixedTimeZone& operator=(const FixedTimeZone&) = delete;

  time_zone::absolute_lookup BreakTime(
      const time_point<seconds>& tp) const override {
    time_zone::absolute_lookup result;
    result.cs = TpToUtc(tp) + offset_sec_;
    result.offset = offset_sec_;
    result.is_dst = false;
    result.abbr = abbr_.c_str();
    return result;
  }

  time_zone::civil_lookup MakeTime(const civil_second& cs) const override {
    time_zone::civil_lookup result;
    result.kind = time_zone::civil_lookup::UNIQUE;
    result.pre = UtcToTp(cs - offset_sec_);
    result.post = result.pre;
    result.trans = result.pre;
    return result;
  }

  bool NextTransition(const time_point<seconds>& tp,
                      time_zone::civil_transition* trans) const override {
    return false;
  }

  bool PrevTransition(const time_point<seconds>& tp,
                      time_zone::civil_transition* trans) const override {
    return false;
  }

  std::string Version() const override { return std::string(); }
  std::string Description() const override { return desc_; }

 private:
  const int32_t offset_sec_;
  const std::string abbr_;
  const std::string desc_;
};

std::unique_ptr<TimeZoneIf> Create(const std::string& name) {
  const auto icu = IcuFunctions::Get();
  if (!icu.available) {
    return nullptr;
  }
  const std::wstring wide_name = Utf8ToUtf16(name);
  const std::wstring win_timezone_name = GetWindowsTimeZoneName(icu, wide_name);
  if (win_timezone_name.empty()) {
    return nullptr;
  }

  REG_TZI_FORMAT base_info;
  std::vector<USHORT> year_list;
  std::vector<REG_TZI_FORMAT> info_list;
  DWORD tz_version = 0;
  if (!GetDynamicTimeZoneInformation(win_timezone_name, &base_info, &year_list,
                                     &info_list, &tz_version)) {
    return nullptr;
  }
  if (year_list.empty() && base_info.DaylightDate.wMonth == 0 &&
      base_info.StandardDate.wMonth == 0) {
    const int32_t offset_seconds =
        -(base_info.Bias + base_info.StandardBias) * 60;
    const std::string desc =
        "WinRegKey=\"" +
        Utf16ToUtf8(win_timezone_name.c_str(), win_timezone_name.size()) +
        "\", WinTzVer=" + std::to_string(tz_version);
    return std::unique_ptr<TimeZoneIf>(new FixedTimeZone(offset_seconds, desc));
  }

  const auto utc_now = civil_second(1970, 1, 1) + std::time(nullptr);

  const TimeZoneInformationMap map(base_info, year_list, info_list);
  const USHORT utc_year = static_cast<USHORT>(utc_now.year());
  USHORT first_year = utc_year - 16;
  USHORT last_year = utc_year + 16;
  bool starts_with_fixed = false;
  bool ends_with_fixed = false;

  if (!year_list.empty()) {
    const auto& first_year_info = info_list.front();
    starts_with_fixed = (first_year_info.StandardDate.wMonth == 0 &&
                         first_year_info.DaylightDate.wMonth == 0);
    ends_with_fixed = (info_list.back().StandardDate.wMonth == 0 &&
                       info_list.back().DaylightDate.wMonth == 0);
    if (starts_with_fixed) {
      first_year = year_list.front();
    } else {
      first_year = std::min<USHORT>(year_list.front() - 3, first_year);
    }
    if (ends_with_fixed) {
      last_year = year_list.back() + 1;
    } else {
      last_year = std::max<USHORT>(year_list.back() + 3, last_year);
    }
  }

  auto transitions = GetOffsetInfo(map, first_year, last_year);

  AbbreviationMapSource abbr_source;
  abbr_source.Add(base_info);
  for (const auto& info : info_list) {
    abbr_source.Add(info);
  }
  return std::unique_ptr<TimeZoneIcuWin>(new TimeZoneIcuWin(
      base_info, year_list, info_list, std::move(abbr_source.MoveToMap()),
      std::move(transitions), starts_with_fixed, ends_with_fixed));
}

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

std::unique_ptr<TimeZoneIf> MakeTimeZoneWinRegistry(const std::string& name) {
  return Create(name);
}

}  // namespace cctz

#endif

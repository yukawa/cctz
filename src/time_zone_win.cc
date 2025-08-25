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
#include <chrono>
#include <deque>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "icu_win.h"
#include "time_zone_fixed.h"
#include "time_zone_if.h"

namespace cctz {
namespace {

const wchar_t kRegistryPath[] =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones";

// The raw structure stored in the "TZI" value of the Windows registry.
// https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-time_zone_information#remarks
#pragma pack(push, 4)
struct REG_TZI_FORMAT {
  LONG Bias;
  LONG StandardBias;
  LONG DaylightBias;
  SYSTEMTIME StandardDate;
  SYSTEMTIME DaylightDate;
};
#pragma pack(pop)

static_assert(std::is_trivially_constructible<REG_TZI_FORMAT>::value,
              "REG_TZI_FORMAT must be trivially constructible");

struct RawOffsetInfo {
  RawOffsetInfo() : offset_seconds(0), dst(false) {}
  std::int32_t offset_seconds;
  bool dst;
};

// Transitions extracted from REG_TZI_FORMAT for the target year. Each
// REG_TZI_FORMAT can provide up to three transitions in a year.
// The most tricky part is that REG_TZI_FORMAT gives us "from" local time and
// "to" offset info. This means that "from" local time cannot be converted to
// UTC time without knowing the "from" offset.
// See ResolveSystemTime() on how REG_TZI_FORMAT is interpreted.
struct RawTransitionInfo {
  RawTransitionInfo() {}
  civil_second from_civil_time;
  RawOffsetInfo to;
};

civil_second TpToUtc(const time_point<seconds>& tp) {
  return civil_second(1970, 1, 1, 0, 0, 0) +
         (tp - std::chrono::time_point_cast<seconds>(
                   std::chrono::system_clock::from_time_t(0)))
             .count();
}

time_point<seconds> UtcToTp(const civil_second& cs) {
  return std::chrono::time_point_cast<seconds>(
             std::chrono::system_clock::from_time_t(0)) +
         seconds(cs - civil_second(1970, 1, 1, 0, 0, 0));
}

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

  auto ustr = std::unique_ptr<wchar_t[]>(new wchar_t[num_counts]);
  const int written_counts =
      ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8str_ptr,
                            utf8str_len, ustr.get(), num_counts);
  if (num_counts != written_counts) {
    return std::wstring();
  }
  return std::wstring(ustr.get(), num_counts);
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

const char* GetCommonAbbreviation(std::int32_t offset_seconds) {
  if (offset_seconds % 1800 == 0) {
    const std::int32_t halfhour_offset = offset_seconds / 1800;
    if (-28 <= halfhour_offset && halfhour_offset <= 28) {
      return kCommonAbbrs[halfhour_offset + 28];
    }
  }
  return nullptr;
}

class AbbreviationMap {
 public:
  AbbreviationMap() = default;
  AbbreviationMap(std::vector<std::int32_t> index_key,
                  std::vector<std::string> index_value)
      : index_key_(std::move(index_key)),
        index_value_(std::move(index_value)) {}

  const char* Get(std::int32_t offset_seconds) const {
    const char* common_abbr = GetCommonAbbreviation(offset_seconds);
    if (common_abbr != nullptr) {
      return common_abbr;
    }
    for (size_t i = 0; i < index_key_.size(); ++i) {
      if (index_key_[i] == offset_seconds) {
        // The returned pointer remains to be valid as long as we do not modify
        // index_value_.
        return index_value_[i].c_str();
      }
    }
    return "";
  }

 private:
  const std::vector<std::int32_t> index_key_;
  const std::vector<std::string> index_value_;
};

class AbbreviationMapBuilder {
 public:
  AbbreviationMapBuilder() = default;

  void Add(const REG_TZI_FORMAT& info) {
    AddInternal(-60 * info.Bias);
    if (info.StandardBias != 0) {
      AddInternal(-60 * (info.Bias + info.StandardBias));
    }
    if (info.DaylightBias != 0) {
      AddInternal(-60 * (info.Bias + info.DaylightBias));
    }
  }

  AbbreviationMap Build() {
    extra_offsets_.shrink_to_fit();
    std::vector<std::int32_t> result;
    extra_offsets_.swap(result);

    std::vector<std::string> abbrs;
    abbrs.reserve(result.size());
    for (const std::int32_t offset : result) {
      const char* common_abbr = GetCommonAbbreviation(offset);
      if (common_abbr == nullptr) {
        abbrs.push_back("GMT" + cctz::FixedOffsetToAbbr(cctz::seconds(offset)));
      }
    }
    return AbbreviationMap(std::move(result), std::move(abbrs));
  }

 private:
  void AddInternal(std::int32_t offset_seconds) {
    if (GetCommonAbbreviation(offset_seconds) != nullptr) {
      return;  // Already exists as a common abbreviation.
    }
    for (size_t i = 0; i < extra_offsets_.size(); ++i) {
      if (extra_offsets_[i] == offset_seconds) {
        return;  // Already exists.
      }
    }
    extra_offsets_.push_back(offset_seconds);
  }

  std::vector<std::int32_t> extra_offsets_;
};

struct LocalTimeInfo {
  LocalTimeInfo() : offset_seconds(0), is_dst(false) {}
  civil_second civil_time;
  std::int32_t offset_seconds;
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

// ARRAY_SIZE(DYNAMIC_TIME_ZONE_INFORMATION::TimeZoneKeyName) == 128.
const size_t kWindowsTimeZoneNameMax = 128;

const cctz::weekday kWeekdays[] = {
    cctz::weekday::sunday,    cctz::weekday::monday,   cctz::weekday::tuesday,
    cctz::weekday::wednesday, cctz::weekday::thursday, cctz::weekday::friday,
    cctz::weekday::saturday};

class TimeZoneRegistry {
 public:
  TimeZoneRegistry(std::vector<REG_TZI_FORMAT> tzi_list,
                   std::uint32_t tzi_list_first_year, std::uint32_t tz_version,
                   AbbreviationMap abbr_map)
      : timezone_list_(std::move(tzi_list)),
        timezone_list_first_year_(tzi_list_first_year),
        tz_version_(tz_version),
        abbr_map_(std::move(abbr_map)) {}

  static TimeZoneRegistry Load(const std::string& iana_tz_name) {
    return LoadInternal(iana_tz_name);
  }

  const std::uint32_t FirstYear() const {
    if (timezone_list_.size() < 2) {
      return 0;
    }
    return timezone_list_first_year_;
  }
  const std::uint32_t LastYear() const {
    if (timezone_list_.size() < 2) {
      return 0;
    }
    // The last entry is the fixed (or the latest) one.
    return timezone_list_first_year_ +
           static_cast<std::uint32_t>(timezone_list_.size() - 2);
  }
  const std::string VersionString() const {
    return std::to_string(tz_version_);
  }
  const bool IsAvailable() const { return !timezone_list_.empty(); }
  const bool IsYearDependent() const { return timezone_list_.size() >= 2; }
  const bool IsFixed() const {
    return timezone_list_.size() == 1 ? IsFixedTimeZone(timezone_list_.back())
                                      : false;
  }

  const bool StartsWithFixed() const {
    return timezone_list_.empty() ? false
                                  : IsFixedTimeZone(timezone_list_.front());
  }
  const bool EndsWithFixed() const {
    return timezone_list_.empty() ? false
                                  : IsFixedTimeZone(timezone_list_.back());
  }

  const char* GetAbbreviation(std::int32_t offset_seconds) const {
    return abbr_map_.Get(offset_seconds);
  }

  std::int32_t GetFixedOffset() const {
    if (timezone_list_.empty()) {
      return 0;
    }
    const auto& base = timezone_list_.back();
    return -60 * (base.Bias + base.StandardBias);
  }

  std::deque<TimeOffsetInfo> GetOffsetInfo(year_t year_start,
                                           year_t year_end) const {
    if (!IsAvailable() || year_start > year_end) {
      return {};
    }
    std::deque<TimeOffsetInfo> result;
    RawOffsetInfo last_base_info;
    for (year_t year = year_start - 1; year <= year_end; ++year) {
      const size_t index =
          year <= timezone_list_first_year_
              ? 0
              : std::min<size_t>(year - timezone_list_first_year_,
                                 timezone_list_.size() - 1);
      const auto transitions = ParseTimeZoneInfo(timezone_list_[index], year);
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
        const std::int32_t offset_diff =
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
              last_info.to.is_dst == info.to.is_dst &&
              last_info.tp == info.tp) {
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

 private:
  TimeZoneRegistry()
      : timezone_list_(), timezone_list_first_year_(0), tz_version_(0) {}

  static TimeZoneRegistry Invalid() { return TimeZoneRegistry(); }

  using ScopedHKey = std::unique_ptr<std::remove_pointer<HKEY>::type,
                                     decltype(&::RegCloseKey)>;

  static ScopedHKey OpenRegistryKey(HKEY root, const wchar_t* sub_key) {
    HKEY hkey = nullptr;
    if (::RegOpenKeyExW(root, sub_key, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
      return ScopedHKey(nullptr, nullptr);
    }
    return ScopedHKey(hkey, ::RegCloseKey);
  }

  static bool ReadTimeZoneInfo(HKEY key, const wchar_t* value_name,
                               REG_TZI_FORMAT* info) {
    REG_TZI_FORMAT format;
    DWORD size = sizeof(REG_TZI_FORMAT);
    LSTATUS reg_result =
        ::RegGetValueW(key, nullptr, value_name, RRF_RT_REG_BINARY, nullptr,
                       reinterpret_cast<LPBYTE>(&format), &size);
    if (reg_result != ERROR_SUCCESS || size != sizeof(REG_TZI_FORMAT)) {
      return false;
    }
    // Apply some limits to the Bias, StandardBias, and DaylightBias to avoid
    // accidental integer overflow.
    const LONG min_bias = -60 * 24 * 7;
    const LONG max_bias = 60 * 24 * 7;
    if (format.Bias < min_bias || max_bias < format.Bias ||
        format.StandardBias < min_bias || max_bias < format.StandardBias ||
        format.DaylightBias < min_bias || max_bias < format.DaylightBias) {
      return false;
    }
    if (!IsValidSystemTime(format.StandardDate) ||
        !IsValidSystemTime(format.DaylightDate)) {
      return false;
    }
    *info = format;
    return true;
  }

  static bool ReadDword(HKEY key, const wchar_t* value_name, DWORD* value) {
    DWORD size = sizeof(DWORD);
    DWORD temp_value;
    LSTATUS reg_result =
        ::RegGetValueW(key, nullptr, value_name, RRF_RT_REG_DWORD, nullptr,
                       reinterpret_cast<LPBYTE>(&temp_value), &size);
    if (reg_result != ERROR_SUCCESS || size != sizeof(DWORD)) {
      return false;
    }
    *value = temp_value;
    return true;
  }

  static bool IsFixedTimeZone(const REG_TZI_FORMAT& format) {
    return format.StandardDate.wMonth == 0 && format.DaylightDate.wMonth == 0;
  }

  static bool IsValidSystemTime(const SYSTEMTIME& st) {
    if (st.wYear == 0) {
      if (st.wMonth == 0) {
        return st.wDay == 0 && st.wDayOfWeek == 0 && st.wHour == 0 &&
               st.wMinute == 0 && st.wSecond == 0 && st.wMilliseconds == 0;
      }
      if (1 <= st.wMonth && st.wMonth <= 12) {
        // Special case for wYear == 0 and st.wMonth != 0:
        // http://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-time_zone_information#members
        return 1 <= st.wDay && st.wDay <= 5 && 0 <= st.wDayOfWeek &&
               st.wDayOfWeek < 7 && 0 <= st.wHour && st.wHour < 24 &&
               0 <= st.wMinute && st.wMinute < 60 && 0 <= st.wSecond &&
               st.wSecond < 60 && 0 <= st.wMilliseconds &&
               st.wMilliseconds < 1000;
      }
      return false;
    }

    return 1601 <= st.wYear && st.wYear <= 30827 && 1 <= st.wMonth &&
           st.wMonth <= 12 && 1 <= st.wDay && st.wDay <= 31 &&
           0 <= st.wDayOfWeek && st.wDayOfWeek < 7 && 0 <= st.wHour &&
           st.wHour < 24 && 0 <= st.wMinute && st.wMinute < 60 &&
           0 <= st.wSecond && st.wSecond < 60 && 0 <= st.wMilliseconds &&
           st.wMilliseconds < 1000;
  }

  static bool ResolveSystemTime(SYSTEMTIME system_time, year_t year,
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

    // Assume IsValidSystemTime() has already validated system_time.wDayOfWeek
    // to be in [0, 6].
    const cctz::weekday target_weekday = kWeekdays[system_time.wDayOfWeek];
    cctz::civil_day target_day;
    if (system_time.wDay == 5) {
      // wDay == 5 means the last weekday of the month.
      year_t tmp_year = year;
      std::int32_t tmp_month = system_time.wMonth + 1;
      if (tmp_month > 12) {
        tmp_month = 1;
        tmp_year += 1;
      }
      target_day =
          prev_weekday(cctz::civil_day(tmp_year, tmp_month, 1), target_weekday);
    } else {
      // Calcurate the first target weekday of the month.
      target_day = next_weekday(
          cctz::civil_day(year, system_time.wMonth, 1) - 1, target_weekday);
      // Adjust the week number based on the wDay field.
      target_day += (system_time.wDay - 1) * 7;
    }

    civil_second cs(target_day.year(), target_day.month(), target_day.day(),
                    system_time.wHour, system_time.wMinute,
                    system_time.wSecond);
    // Special rule for "23:59:59.999".
    // https://stackoverflow.com/a/47106207
    if (cs.hour() == 23 && cs.minute() == 59 && cs.second() == 59 &&
        system_time.wMilliseconds == 999) {
      cs += 1;
    }
    *result = cs;
    return true;
  }

  static TimeZoneRegistry LoadInternal(const std::string& iana_tz_name) {
    const std::wstring key_name =
        icu::ConvertToWindowsTimeZoneId(Utf8ToUtf16(iana_tz_name));
    if (key_name.empty()) {
      return TimeZoneRegistry::Invalid();
    }

    if (key_name.empty() || key_name.size() > kWindowsTimeZoneNameMax) {
      return TimeZoneRegistry::Invalid();
    }

    ScopedHKey hkey_timezone_root =
        OpenRegistryKey(HKEY_LOCAL_MACHINE, kRegistryPath);
    if (!hkey_timezone_root) {
      return TimeZoneRegistry::Invalid();
    }

    DWORD timezone_version = 0;
    if (!ReadDword(hkey_timezone_root.get(), L"TzVersion", &timezone_version)) {
      return TimeZoneRegistry::Invalid();
    }

    ScopedHKey hkey_timezone =
        OpenRegistryKey(hkey_timezone_root.get(), key_name.c_str());
    if (!hkey_timezone) {
      return TimeZoneRegistry::Invalid();
    }
    std::vector<REG_TZI_FORMAT> timezone_list;
    DWORD first_year = 0;
    DWORD last_year = 0;

    ScopedHKey hkey_dynamic_years =
        OpenRegistryKey(hkey_timezone.get(), L"Dynamic DST");
    if (hkey_dynamic_years) {
      if (!ReadDword(hkey_dynamic_years.get(), L"FirstEntry", &first_year)) {
        return TimeZoneRegistry::Invalid();
      }
      if (!ReadDword(hkey_dynamic_years.get(), L"LastEntry", &last_year)) {
        return TimeZoneRegistry::Invalid();
      }
      if (first_year > last_year) {
        return TimeZoneRegistry::Invalid();
      }

      const size_t year_count = static_cast<size_t>(
          static_cast<std::int64_t>(last_year) - first_year + 1);
      timezone_list.reserve(year_count);
      for (DWORD year = first_year; year <= last_year; ++year) {
        const std::wstring key = std::to_wstring(year);
        REG_TZI_FORMAT format;
        if (!ReadTimeZoneInfo(hkey_dynamic_years.get(), key.c_str(), &format)) {
          return TimeZoneRegistry::Invalid();
        }
        timezone_list.push_back(format);
      }
    }
    REG_TZI_FORMAT base_tzi;
    if (!ReadTimeZoneInfo(hkey_timezone.get(), L"TZI", &base_tzi)) {
      return TimeZoneRegistry::Invalid();
    }
    timezone_list.push_back(base_tzi);
    timezone_list.shrink_to_fit();

    AbbreviationMapBuilder abbr_map_builder;
    for (const auto& info : timezone_list) {
      abbr_map_builder.Add(info);
    }

    return TimeZoneRegistry(std::move(timezone_list), first_year,
                            timezone_version,
                            abbr_map_builder.Build());
  }

  static std::deque<RawTransitionInfo> ParseTimeZoneInfo(
      const REG_TZI_FORMAT& format, year_t year) {
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

    std::deque<RawTransitionInfo> result;
    if (!(has_std_begin && std_begin == year_begin) &&
        !(has_dst_begin && dst_begin == year_begin)) {
      RawTransitionInfo info;
      info.from_civil_time = year_begin;
      info.to.offset_seconds = -60 * format.Bias;
      info.to.dst = false;
      result.push_back(info);
    }
    if (has_std_begin) {
      RawTransitionInfo info;
      info.from_civil_time = std_begin;
      info.to.offset_seconds = -60 * (format.Bias + format.StandardBias);
      info.to.dst = false;
      result.push_back(info);
    }
    if (has_dst_begin) {
      RawTransitionInfo info;
      info.from_civil_time = dst_begin;
      info.to.offset_seconds = -60 * (format.Bias + format.DaylightBias);
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

  // This field is also used to indicate whether the object is valid or not.
  //  - Size of 0: Invalid object (e.g. failed to load from the registry).
  //  - Size of 1: No per-year override. `timezone_list_first_year_` is ignored.
  //  - Size of N: Per-year override for N years with extrapolations with the
  //               first/last entry.
  const std::vector<REG_TZI_FORMAT> timezone_list_;
  const std::uint32_t timezone_list_first_year_;
  const std::uint32_t tz_version_;
  const AbbreviationMap abbr_map_;
};

class TransitionCache {
 public:
  static TransitionCache Create(const TimeZoneRegistry& timezone_registry) {
    return CreateInternal(timezone_registry);
  }

  bool Cached(const civil_second& cs) const {
    return (transitions_.front().earlier_cs() <= cs &&
            cs <= transitions_.back().later_cs()) ||
           (starts_with_fixed_ && cs < transitions_.front().earlier_cs()) ||
           (ends_with_fixed_ && transitions_.back().later_cs() < cs);
  }
  bool Cached(const time_point<seconds>& tp) const {
    return (transitions_.front().tp <= tp && tp <= transitions_.back().tp) ||
           (starts_with_fixed_ && tp < transitions_.front().tp) ||
           (ends_with_fixed_ && transitions_.back().tp < tp);
  }

  const std::deque<TimeOffsetInfo>& Get() const { return transitions_; }

 private:
  TransitionCache(std::deque<TimeOffsetInfo> transitions,
                  bool starts_with_fixed, bool ends_with_fixed)
      : transitions_(std::move(transitions)),
        starts_with_fixed_(starts_with_fixed),
        ends_with_fixed_(ends_with_fixed) {}

  static TransitionCache CreateInternal(
      const TimeZoneRegistry& timezone_registry) {
    const auto utc_now = civil_second(1970, 1, 1) + std::time(nullptr);

    const year_t utc_year = utc_now.year();
    year_t first_year = utc_year - 16;
    year_t last_year = utc_year + 16;
    bool starts_with_fixed = false;
    bool ends_with_fixed = false;

    if (timezone_registry.IsYearDependent()) {
      starts_with_fixed = timezone_registry.StartsWithFixed();
      ends_with_fixed = timezone_registry.EndsWithFixed();
      if (starts_with_fixed) {
        first_year = timezone_registry.FirstYear();
      } else {
        first_year =
            std::min<year_t>(timezone_registry.FirstYear() - 3, first_year);
      }
      if (ends_with_fixed) {
        last_year = timezone_registry.LastYear() + 1;
      } else {
        last_year =
            std::max<year_t>(timezone_registry.LastYear() + 3, last_year);
      }
    }
    return TransitionCache(
        timezone_registry.GetOffsetInfo(first_year, last_year),
        starts_with_fixed, ends_with_fixed);
  }

  const std::deque<TimeOffsetInfo> transitions_;
  const bool starts_with_fixed_;
  const bool ends_with_fixed_;
};

class TimeZoneWinRegistry final : public TimeZoneIf {
 public:
  TimeZoneWinRegistry(TimeZoneRegistry timezone_map,
                      TransitionCache transition_cache)
      : tz_reg_(std::move(timezone_map)),
        transition_cache_(std::move(transition_cache)) {}

  TimeZoneWinRegistry(const TimeZoneWinRegistry&) = delete;
  TimeZoneWinRegistry(TimeZoneWinRegistry&&) = delete;
  TimeZoneWinRegistry& operator=(const TimeZoneWinRegistry&) = delete;

  // TimeZoneIf implementations.
  time_zone::absolute_lookup BreakTime(
      const time_point<seconds>& tp) const override {
    const auto utc = TpToUtc(tp);
    const std::deque<TimeOffsetInfo>& offsets =
        transition_cache_.Cached(tp)
            ? transition_cache_.Get()
            : tz_reg_.GetOffsetInfo(utc.year() - 1, utc.year() + 1);
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
    const std::int32_t offset_seconds = info->offset_seconds;
    time_zone::absolute_lookup result;
    result.cs = utc + offset_seconds;
    result.offset = offset_seconds;
    result.is_dst = info->is_dst;
    result.abbr = tz_reg_.GetAbbreviation(offset_seconds);
    return result;
  }

  time_zone::civil_lookup MakeTime(const civil_second& cs) const override {
    const auto& offsets =
        transition_cache_.Cached(cs)
            ? transition_cache_.Get()
            : tz_reg_.GetOffsetInfo(cs.year() - 1, cs.year() + 1);
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
      const auto& current = offsets[i];
      if (current.earlier_cs() <= cs && cs < current.later_cs()) {
        time_zone::civil_lookup result;
        result.kind = current.kind;
        result.pre = UtcToTp(cs - current.from.offset_seconds);
        result.post = UtcToTp(cs - current.to.offset_seconds);
        result.trans = current.tp;
        return result;
      }
      if ((i + 1) < offsets.size()) {
        const auto& next = offsets[i + 1];
        if (current.later_cs() <= cs && cs < next.earlier_cs()) {
          time_zone::civil_lookup result;
          result.kind = time_zone::civil_lookup::UNIQUE;
          result.pre = UtcToTp(cs - current.to.offset_seconds);
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
    const auto& transitions = transition_cache_.Get();
    if (transitions.empty()) {
      return false;
    }
    const auto it = std::upper_bound(
        transitions.begin(), transitions.end(), tp,
        [](const time_point<seconds>& value, const TimeOffsetInfo& info) {
          return value < info.tp;
        });
    if (it == transitions.end()) {
      return false;
    }
    trans->from = it->from.civil_time;
    trans->to = it->to.civil_time;
    return true;
  }

  bool PrevTransition(const time_point<seconds>& tp,
                      time_zone::civil_transition* trans) const override {
    const auto& transitions = transition_cache_.Get();
    if (transitions.empty()) {
      return false;
    }
    auto it = std::lower_bound(
        transitions.begin(), transitions.end(), tp,
        [](const TimeOffsetInfo& info, const time_point<seconds>& value) {
          return info.tp < value;
        });
    if (it == transitions.begin()) {
      return false;
    }
    --it;
    trans->from = it->from.civil_time;
    trans->to = it->to.civil_time;
    return true;
  }

  std::string Version() const override { return std::string(); }

  std::string Description() const override {
    return "WinTzVer=" + tz_reg_.VersionString();
  }

 private:
  const TimeZoneRegistry tz_reg_;
  const TransitionCache transition_cache_;
};

class FixedTimeZone final : public TimeZoneIf {
 public:
  explicit FixedTimeZone(std::int32_t offset_sec, std::string desc)
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
  const std::int32_t offset_sec_;
  const std::string abbr_;
  const std::string desc_;
};

std::unique_ptr<TimeZoneIf> MakeTimeZoneIfInternal(const std::string& name) {
  TimeZoneRegistry timezone_registry = TimeZoneRegistry::Load(name);
  if (!timezone_registry.IsAvailable()) {
    return nullptr;
  }

  if (timezone_registry.IsFixed()) {
    const std::int32_t offset_seconds = timezone_registry.GetFixedOffset();
    std::string desc = "WinTzVer=" + timezone_registry.VersionString();
    return std::unique_ptr<TimeZoneIf>(
        new FixedTimeZone(offset_seconds, std::move(desc)));
  }

  auto cache = TransitionCache::Create(timezone_registry);
  return std::unique_ptr<TimeZoneWinRegistry>(
      new TimeZoneWinRegistry(std::move(timezone_registry), std::move(cache)));
}

}  // namespace

std::unique_ptr<TimeZoneIf> MakeTimeZoneWinRegistry(const std::string& name) {
  return MakeTimeZoneIfInternal(name);
}

}  // namespace cctz

#endif

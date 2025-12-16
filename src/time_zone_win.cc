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

#include <algorithm>
#include <chrono>
#include <deque>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "time_zone_fixed.h"
#include "time_zone_if.h"
#include "tzfile.h"
#include "cctz/zone_info_source.h"

namespace cctz {
namespace {

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

const cctz::weekday kWeekdays[] = {
    cctz::weekday::sunday,    cctz::weekday::monday,   cctz::weekday::tuesday,
    cctz::weekday::wednesday, cctz::weekday::thursday, cctz::weekday::friday,
    cctz::weekday::saturday};

bool ResolveSystemTime(const WinSystemTime& system_time, year_t year,
                       civil_second* result) {
  const year_t system_time_year = static_cast<year_t>(system_time.year);
  if (system_time_year == year) {
    *result = civil_second(system_time_year, system_time.month,
                            system_time.day, system_time.hour,
                            system_time.minute, system_time.second);
    return true;
  }
  if (system_time_year != 0) {
    return false;
  }

  // Assume the loader has already validated day_of_week to be in [0, 6].
  const cctz::weekday target_weekday = kWeekdays[system_time.day_of_week];
  cctz::civil_day target_day;
  if (system_time.day == 5) {
    // SYSTEMTIME::wDay == 5 means the last weekday of the month.
    year_t tmp_year = year;
    std::int_fast32_t tmp_month = system_time.month + 1;
    if (tmp_month > 12) {
      tmp_month = 1;
      tmp_year += 1;
    }
    target_day =
        prev_weekday(cctz::civil_day(tmp_year, tmp_month, 1), target_weekday);
  } else {
    // Calcurate the first target weekday of the month.
    target_day = next_weekday(cctz::civil_day(year, system_time.month, 1) - 1,
                              target_weekday);
    // Adjust the week number based on the wDay field.
    target_day += (system_time.day - 1) * 7;
  }

  civil_second cs(target_day.year(), target_day.month(), target_day.day(),
                  system_time.hour, system_time.minute, system_time.second);
  // Special rule for "23:59:59.999".
  // https://stackoverflow.com/a/47106207
  if (cs.hour() == 23 && cs.minute() == 59 && cs.second() == 59 &&
      system_time.milliseconds == 999) {
    cs += 1;
  }
  *result = cs;
  return true;
}

struct RawOffsetInfo {
  RawOffsetInfo() : offset_seconds(0), dst(false) {}
  std::int_fast32_t offset_seconds;
  bool dst;
};

// Transitions extracted from WinTimeZoneRegistryEntry (==REG_TZI_FORMAT) for
// the target year. Each WinTimeZoneRegistryEntry can provide up to three
// transitions in a year.
// The most tricky part is that WinTimeZoneRegistryEntry gives us localtime in
// "from" offset whereas corresponding Biases are "to" offset. This means that
// "from" localtime cannot be converted to UTC time without knowing the "from"
// offset.
// See ResolveSystemTime() on how WinTimeZoneRegistryEntry is interpreted.
struct RawTransitionInfo {
  civil_second from_civil_time;
  RawOffsetInfo to;
};

std::deque<RawTransitionInfo> ParseTimeZoneInfo(
    const WinTimeZoneRegistryEntry& format, year_t year) {
  const civil_second year_begin(year, 1, 1, 0, 0, 0);
  bool has_std_begin = false;
  civil_second std_begin;
  if (format.standard_date.month != 0) {
    has_std_begin = ResolveSystemTime(format.standard_date, year, &std_begin);
  }
  bool has_dst_begin = false;
  civil_second dst_begin;
  if (format.daylight_date.month != 0) {
    has_dst_begin = ResolveSystemTime(format.daylight_date, year, &dst_begin);
  }

  std::deque<RawTransitionInfo> result;
  if (!(has_std_begin && std_begin == year_begin) &&
      !(has_dst_begin && dst_begin == year_begin)) {
    RawTransitionInfo info;
    info.from_civil_time = year_begin;
    info.to.offset_seconds = -60 * format.bias;
    info.to.dst = false;
    result.push_back(info);
  }
  if (has_std_begin) {
    RawTransitionInfo info;
    info.from_civil_time = std_begin;
    info.to.offset_seconds = -60 * (format.bias + format.standard_bias);
    info.to.dst = false;
    result.push_back(info);
  }
  if (has_dst_begin) {
    RawTransitionInfo info;
    info.from_civil_time = dst_begin;
    info.to.offset_seconds = -60 * (format.bias + format.daylight_bias);
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

struct LocalTimeInfo {
  LocalTimeInfo() : offset_seconds(0), is_dst(false) {}
  civil_second civil_time;
  std::int_fast32_t offset_seconds;
  bool is_dst;
};

struct TimeOffsetInfo {
  TimeOffsetInfo() : kind(time_zone::civil_lookup::UNIQUE) {}

  LocalTimeInfo from;
  LocalTimeInfo to;
  time_point<seconds> tp;
  time_zone::civil_lookup::civil_kind kind;
};

// Collect transitions for a timezone using ICU
std::deque<TimeOffsetInfo> CollectTransitions(
    const WinTimeZoneRegistryInfo& info) {
  std::deque<TimeOffsetInfo> result;

  if (info.entries.size() == 1) {
    // No transitions found; add a single UNIQUE entry with UTC offset 0.
    const WinTimeZoneRegistryEntry entry = info.entries[0];
    TimeOffsetInfo offset_info;
    offset_info.from.civil_time = civil_second(info.first_year, 1, 1, 0, 0, 0);
    offset_info.from.is_dst = false;
    offset_info.from.offset_seconds = -60 * entry.bias;
    offset_info.to = offset_info.from;
    offset_info.tp = UtcToTp(offset_info.from.civil_time - offset_info.from.offset_seconds);
    offset_info.kind = time_zone::civil_lookup::UNIQUE;
    result.push_back(offset_info);
    return result;
  }

  RawOffsetInfo last_base_info;
  for (size_t i = 0; i < info.entries.size(); ++i) {
    const year_t year = info.first_year + i;
    const auto transitions = ParseTimeZoneInfo(info.entries[i], year);
    if (i == 0) {
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
      const std::int_fast32_t offset_diff =
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

std::vector<Transition> ToTransitions(const std::deque<TimeOffsetInfo>& offsets) {
  std::vector<Transition> result;
  for (const auto& offset : offsets) {
    Transition trans;
    trans.time = ToUnixSeconds(offset.tp);
    trans.offset = offset.to.offset_seconds;
    trans.is_dst = offset.to.is_dst;
    trans.abbr = "GMT" + cctz::FixedOffsetToAbbr(cctz::seconds(offset.to.offset_seconds));
    result.push_back(trans);
  }
  return result;
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

bool IsFixedTimeZone(const WinTimeZoneRegistryEntry& entry) {
  return entry.standard_date.month == 0 && entry.daylight_date.month == 0;
}

bool EndsWithFixed(const WinTimeZoneRegistryInfo& info) {
  return info.entries.empty() ? false : IsFixedTimeZone(info.entries.back());
}

std::string ToTzString(const WinTimeZoneRegistryInfo& info) {
  if (info.entries.empty()) {
    return "";
  }
  const auto last_entry = info.entries.back();
  const auto std_offset = 60 * (last_entry.bias + last_entry.standard_bias);
  const std::string std_tz =
      std_offset == 0
          ? "GMT0"
          : "<GMT" + cctz::FixedOffsetToAbbr(cctz::seconds(-std_offset)) + ">" +
                std::to_string(std_offset / 3600);
  if (EndsWithFixed(info)) {
    return std_tz;
  }
  const auto dst_offset = 60 * (last_entry.bias + last_entry.daylight_bias);
  const std::string dst_tz =
      dst_offset == 0
          ? "GMT0"
          : "<GMT" + cctz::FixedOffsetToAbbr(cctz::seconds(-dst_offset)) + ">" +
                std::to_string(dst_offset / 3600);
  const auto last_daylight_date = last_entry.daylight_date;
  const std::string dst_start =
      last_daylight_date.month == 0
          ? ""
          : ",M" + std::to_string(last_daylight_date.month) + '.' +
                std::to_string(last_daylight_date.day) + '.' +
                std::to_string(last_daylight_date.day_of_week) + '/' +
                std::to_string(last_daylight_date.hour) + ":00:00";
  const auto last_standard_date = last_entry.standard_date;
  const std::string std_start =
      last_standard_date.month == 0
          ? ""
          : ",M" + std::to_string(last_standard_date.month) + '.' +
                std::to_string(last_standard_date.day) + '.' +
                std::to_string(last_standard_date.day_of_week) + '/' +
                std::to_string(last_standard_date.hour) + ":00:00";
  return std_tz + dst_tz + dst_start + std_start;
}

class WinZoneInfoSource : public ZoneInfoSource {
 public:
  WinZoneInfoSource() = delete;
  WinZoneInfoSource(const WinZoneInfoSource&) = delete;
  WinZoneInfoSource& operator=(const WinZoneInfoSource&) = delete;

  WinZoneInfoSource(std::vector<char>&& data)
      : data_(std::move(data)) {
  }

  // ZoneInfoSource interface implementation
  std::size_t Read(void* ptr, std::size_t size) override;
  int Skip(std::size_t offset) override;
  std::string Version() const override;

 private:
  // The generated TZDATA binary data
  const std::vector<char> data_;

  // Current read position
  std::size_t pos_ = 0;
};

// Implementation of WinZoneInfoSource methods
std::size_t WinZoneInfoSource::Read(void* ptr, std::size_t size) {
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

int WinZoneInfoSource::Skip(std::size_t offset) {
  const std::size_t new_pos = pos_ + offset;
  if (new_pos > data_.size()) {
    return -1;  // Would go past EOF
  }
  pos_ = new_pos;
  return 0;
}

std::string WinZoneInfoSource::Version() const {
  return "";
}

// Factory function implementation
std::unique_ptr<WinZoneInfoSource> CreateWinZoneInfoSourceInternal(
    const WinTimeZoneRegistryInfo& info) {
  std::vector<Transition> transitions = ToTransitions(CollectTransitions(info));

  // Build unique transition types and deduplicated abbreviations
  std::vector<TransitionType> types;
  std::string abbr_string;
  // Keep track of (start_index_in_abbr_string, length) for each abbreviation.
  std::vector<std::pair<size_t, size_t>> abbr_range_map;

  for (const auto& trans : transitions) {
    const auto key = std::make_pair(trans.offset, trans.is_dst);

    bool type_found = false;
    for (size_t type_index = 0; type_index < types.size(); ++type_index) {
      const auto& type = types[type_index];
      if (type.offset == trans.offset && type.is_dst == trans.is_dst) {
        type_found = true;
        break;
      }
    }
    if (type_found) {
      continue;  // Skip if this type already exists
    }

    if (types.size() >= std::numeric_limits<uint8_t>::max()) {
      return nullptr;
    }

    TransitionType type;
    type.offset = trans.offset;
    type.is_dst = trans.is_dst;

    // Check if abbreviation already exists
    bool abbr_found = false;
    for (size_t abbr_index = 0; abbr_index < abbr_range_map.size();
        ++abbr_index) {
      const auto& range = abbr_range_map[abbr_index];
      if (range.second != trans.abbr.size()) {
        continue;  // Length mismatch, skip
      }
      const int memcmp_result = std::memcmp(abbr_string.data() + range.first,
                                            trans.abbr.data(), range.second);
      if (memcmp_result == 0) {
        type.abbr_idx = static_cast<uint8_t>(abbr_index);
        abbr_found = true;
        break;
      }
    }

    if (!abbr_found) {
      // Add new abbreviation
      if (abbr_range_map.size() >= std::numeric_limits<uint8_t>::max()) {
        return nullptr;  // Too many abbreviations
      }
      type.abbr_idx = static_cast<uint8_t>(abbr_string.size());
      abbr_range_map.push_back(
          std::make_pair(abbr_string.size(), trans.abbr.size()));
      abbr_string += trans.abbr;
      abbr_string += '\0';
    }

    types.push_back(type);
  }

  // Build TZDATA binary format
  std::vector<char> data;

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
  data.resize(sizeof(tzhead));

  // Fill first header with version 2
  tzhead* hdr1 = reinterpret_cast<tzhead*>(data.data());
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
    data.insert(data.end(), buf, buf + 4);
  }

  // Write transition type indices
  for (const auto& trans : trans32) {
    for (size_t type_index = 0; type_index < types.size(); ++type_index) {
      const auto& type = types[type_index];
      if (type.offset == trans.offset && type.is_dst == trans.is_dst) {
        data.push_back(type_index);
        break;
      }
    }
  }

  // Write transition types
  for (const auto& type : types) {
    char buf[4];
    Encode32(buf, type.offset);
    data.insert(data.end(), buf, buf + 4);
    data.push_back(type.is_dst ? 1 : 0);
    data.push_back(type.abbr_idx);
  }

  // Write abbreviation string
  data.insert(data.end(), abbr_string.begin(), abbr_string.end());

  // No leap seconds, standard/wall indicators, or UTC/local indicators

  // === VERSION 2 SECTION (64-bit) ===
  // Second header
  std::size_t hdr2_pos = data.size();
  data.resize(data.size() + sizeof(tzhead));
  tzhead* hdr2 = reinterpret_cast<tzhead*>(data.data() + hdr2_pos);
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
    data.insert(data.end(), buf, buf + 8);
  }

  // Write transition type indices
  for (const auto& trans : transitions) {
    for (size_t type_index = 0; type_index < types.size(); ++type_index) {
      const auto& type = types[type_index];
      if (type.offset == trans.offset && type.is_dst == trans.is_dst) {
        data.push_back(type_index);
        break;
      }
    }
  }

  // Write transition types again
  for (const auto& type : types) {
    char buf[4];
    Encode32(buf, type.offset);
    data.insert(data.end(), buf, buf + 4);
    data.push_back(type.is_dst ? 1 : 0);
    data.push_back(type.abbr_idx);
  }

  // Write abbreviation string again
  data.insert(data.end(), abbr_string.begin(), abbr_string.end());

  // No leap seconds, standard/wall indicators, or UTC/local indicators

  std::string spec_str = "\n" + ToTzString(info) + "\n";
  data.insert(data.end(), spec_str.begin(), spec_str.end());

  return std::make_unique<WinZoneInfoSource>(std::move(data));
}

}  // namespace

std::unique_ptr<ZoneInfoSource> CreateWinZoneInfoSource(
    WinTimeZoneRegistryInfo info) {
  return CreateWinZoneInfoSourceInternal(info);
}

}  // namespace cctz

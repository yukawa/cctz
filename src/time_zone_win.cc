// Copyright 2026 Google Inc. All Rights Reserved.
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
#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "cctz/zone_info_source.h"
#include "time_zone_fixed.h"
#include "time_zone_if.h"

namespace cctz {
namespace {

const year_t kTransitionStartYear = 1970;

const cctz::weekday kWeekdays[] = {
    cctz::weekday::sunday,    cctz::weekday::monday,   cctz::weekday::tuesday,
    cctz::weekday::wednesday, cctz::weekday::thursday, cctz::weekday::friday,
    cctz::weekday::saturday};

// Structure to hold transition information
struct TransitionInfo {
  TransitionInfo() : time(0), offset(0), is_dst(false) {}
  std::int_fast64_t time;    // Unix timestamp
  std::int_fast32_t offset;  // Seconds east of UTC
  bool is_dst;               // Is daylight saving time
};

struct Transition {
  Transition() : time(0), type_idx(0) {}
  std::int_fast64_t time;      // Unix timestamp
  std::uint_fast8_t type_idx;  // Index into transition types
};

// Structure to hold transition type
struct TransitionType {
  TransitionType() : abbr_idx(0), offset(0), is_dst(false) {}
  std::uint_fast8_t abbr_idx;  // Index into abbreviation string
  std::int_fast32_t offset;    // Seconds east of UTC
  bool is_dst;                 // Is daylight saving time
};

struct TransitionTable {
  const std::vector<Transition> transitions;
  const std::vector<TransitionType> transition_types;
  const std::string abbreviation_table;
  const std::vector<std::size_t> abbreviation_indices;
  const std::string prolepic_tz_string;
};

class TransitionTableBuilder {
 public:
  static TransitionTable Build(const WinTimeZoneRegistryInfo& info) {
    TransitionTableBuilder builder;
    builder.Initialize(info);
    if (builder.overflowed_) {
      // Return an empty table on overflow.
      return TransitionTable{};
    }
    return TransitionTable{builder.transitions_, builder.transition_types_,
                           builder.abbreviation_table_,
                           builder.abbreviation_indices_,
                           builder.prolepic_tz_string_};
  }

 private:
  TransitionTableBuilder()
      : has_pre_initial_offset_(false), overflowed_(false) {}

  struct OffsetDstPair {
    OffsetDstPair() : offset_seconds(0), dst(false) {}
    OffsetDstPair(std::int_fast32_t offset_seconds_, bool dst_)
        : offset_seconds(offset_seconds_), dst(dst_) {}
    OffsetDstPair(const OffsetDstPair& other) = default;
    std::int_fast32_t offset_seconds;
    bool dst;
  };

  void Initialize(const WinTimeZoneRegistryInfo& info) {
    if (info.entries.empty()) {
      return;
    }

    const year_t first_year =
        info.entries.size() == 1
            ? kTransitionStartYear
            : std::min<cctz::year_t>(info.first_year, kTransitionStartYear);

    const auto& first_entry = info.entries[0];
    if (IsFixedTimeZone(first_entry)) {
      // Add an initial UNIQUE transition.
      civil_second first_civil_second(first_year, 1, 1, 0, 0, 0);
      TransitionInfo initial_info;
      const std::int_fast32_t offset_seconds = -60 * first_entry.bias;
      initial_info.time =
          seconds(first_civil_second - (-60 * first_entry.bias) -
                  civil_second(1970, 1, 1, 0, 0, 0))
              .count();
      initial_info.offset = offset_seconds;
      initial_info.is_dst = false;
      AddTransition(initial_info);
    } else {
      ProcessEntry(first_entry, first_year - 1);
    }

    if (info.entries.size() == 1) {
      ProcessEntry(first_entry, first_year);
    } else {
      const year_t last_year =
          info.first_year + static_cast<year_t>(info.entries.size());
      for (cctz::year_t year = first_year; year < last_year; ++year) {
        ProcessEntry(
            info.entries[year < info.first_year
                             ? 0
                             : static_cast<size_t>(year - info.first_year)],
            year);
        if (overflowed_) {
          return;
        }
      }
    }
    prolepic_tz_string_ = ToTzString(info.entries.back());
  }

  static bool ResolveSystemTime(const WinSystemTime& system_time, year_t year,
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

  void ProcessEntry(const WinTimeZoneRegistryEntry& format, year_t year) {
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

    if ((!has_std_begin || std_begin != year_begin) &&
        (!has_dst_begin || dst_begin != year_begin)) {
      TryAddOffset(year_begin, OffsetDstPair{-60 * format.bias, false});
    }

    if (has_dst_begin) {
      if (has_std_begin) {
        if (std_begin < dst_begin) {
          TryAddOffset(
              std_begin,
              OffsetDstPair{-60 * (format.bias + format.standard_bias), false});
          TryAddOffset(
              dst_begin,
              OffsetDstPair{-60 * (format.bias + format.daylight_bias), true});
        } else {
          TryAddOffset(
              dst_begin,
              OffsetDstPair{-60 * (format.bias + format.daylight_bias), true});
          TryAddOffset(
              std_begin,
              OffsetDstPair{-60 * (format.bias + format.standard_bias), false});
        }
      } else {
        TryAddOffset(
            dst_begin,
            OffsetDstPair{-60 * (format.bias + format.daylight_bias), true});
      }
    } else {
      if (has_std_begin) {
        TryAddOffset(
            std_begin,
            OffsetDstPair{-60 * (format.bias + format.standard_bias), false});
      }
    }
  }

  void TryAddOffset(civil_second from_civil_time, OffsetDstPair to_offset) {
    OffsetDstPair last_offset;

    if (transitions_.empty()) {
      if (!has_pre_initial_offset_) {
        pre_initial_offset_ = to_offset;
        has_pre_initial_offset_ = true;
        return;
      }

      const auto pre_initial_offset = pre_initial_offset_;
      pre_initial_offset_ = to_offset;

      // We want to start from non-DST transtion.
      if (to_offset.dst) {
        return;
      }
      if (pre_initial_offset.offset_seconds == to_offset.offset_seconds &&
          pre_initial_offset.dst == to_offset.dst) {
        return;
      }
      last_offset = pre_initial_offset;
    } else {
      // Otherwise, get the last offset from the last transition.
      const auto& last_info = transition_types_[transitions_.back().type_idx];
      last_offset.dst = last_info.is_dst;
      last_offset.offset_seconds = last_info.offset;
    }

    if (last_offset.offset_seconds == to_offset.offset_seconds &&
        last_offset.dst == to_offset.dst) {
      // No change.
      return;
    }
    TransitionInfo new_info;
    new_info.time = seconds(from_civil_time - last_offset.offset_seconds -
                            civil_second(1970, 1, 1, 0, 0, 0))
                        .count();
    new_info.offset = to_offset.offset_seconds;
    new_info.is_dst = to_offset.dst;
    AddTransition(new_info);
  }

  void AddTransition(const TransitionInfo& transition_info) {
    if (overflowed_) {
      return;
    }

    const std::string abbr =
        "UTC" + cctz::FixedOffsetToAbbr(cctz::seconds(transition_info.offset));

    bool abbr_found = false;
    size_t abbr_index = 0;
    for (size_t index : abbreviation_indices_) {
      if (std::memcmp(&abbreviation_table_[index], abbr.c_str(),
                      abbr.size() + 1) == 0) {
        abbr_found = true;
        abbr_index = index;
        break;
      }
    }
    if (!abbr_found) {
      abbr_index = abbreviation_table_.size();
      if (abbr_index > std::numeric_limits<uint8_t>::max()) {
        // Too many abbreviations.
        overflowed_ = true;
        return;
      }

      abbreviation_table_.append(abbr);
      abbreviation_table_.push_back('\0');
      abbreviation_indices_.push_back(abbr_index);
      abbr_found = true;
    }

    bool type_found = false;
    size_t type_index = 0;
    for (size_t i = 0; i < transition_types_.size(); ++i) {
      const TransitionType& tt = transition_types_[i];
      if (tt.offset == transition_info.offset &&
          tt.is_dst == transition_info.is_dst && tt.abbr_idx == abbr_index) {
        type_found = true;
        type_index = i;
        break;
      }
    }

    if (!type_found) {
      type_index = transition_types_.size();
      if (type_index > std::numeric_limits<uint8_t>::max()) {
        // Too many transition types.
        overflowed_ = true;
        return;
      }
      TransitionType new_type;
      new_type.offset = transition_info.offset;
      new_type.is_dst = transition_info.is_dst;
      new_type.abbr_idx = static_cast<uint8_t>(abbr_index);
      transition_types_.push_back(new_type);
      type_found = true;
    }

    Transition transition;
    transition.time = transition_info.time;
    transition.type_idx = static_cast<uint8_t>(type_index);
    transitions_.push_back(transition);
  }

  static bool IsFixedTimeZone(const WinTimeZoneRegistryEntry& entry) {
    return entry.standard_date.month == 0 && entry.daylight_date.month == 0;
  }

  std::vector<Transition> transitions_;
  std::vector<TransitionType> transition_types_;
  std::string abbreviation_table_;
  std::vector<std::size_t> abbreviation_indices_;
  std::string prolepic_tz_string_;
  // DST offset used to calculate the first non-DST transition.
  OffsetDstPair pre_initial_offset_;
  bool has_pre_initial_offset_;
  bool overflowed_;
};

class WinZoneInfoSource : public ZoneInfoSource {
 public:
  WinZoneInfoSource() = delete;
  WinZoneInfoSource(const WinZoneInfoSource&) = delete;
  WinZoneInfoSource& operator=(const WinZoneInfoSource&) = delete;

  WinZoneInfoSource(std::vector<char>&& data) : data_(std::move(data)) {}

  // ZoneInfoSource interface implementation
  std::size_t Read(void* ptr, std::size_t size) override {
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

  int Skip(std::size_t offset) override {
    const std::size_t new_pos = pos_ + offset;
    if (new_pos > data_.size()) {
      return -1;  // Would go past EOF
    }
    pos_ = new_pos;
    return 0;
  }

  std::string Version() const override { return ""; }

 private:
  // The generated TZDATA binary data
  const std::vector<char> data_;

  // Current read position
  std::size_t pos_ = 0;
};

// Helper to encode big-endian integers
void EncodeInt32(char* dst, std::int_fast32_t value) {
  dst[0] = static_cast<char>((value >> 24) & 0xff);
  dst[1] = static_cast<char>((value >> 16) & 0xff);
  dst[2] = static_cast<char>((value >> 8) & 0xff);
  dst[3] = static_cast<char>(value & 0xff);
}

void EncodeUInt32(char* dst, std::uint_fast32_t value) {
  dst[0] = static_cast<char>((value >> 24) & 0xff);
  dst[1] = static_cast<char>((value >> 16) & 0xff);
  dst[2] = static_cast<char>((value >> 8) & 0xff);
  dst[3] = static_cast<char>(value & 0xff);
}

void PushBackInt32(std::vector<char>* dst, std::int_fast32_t value) {
  dst->push_back(static_cast<char>((value >> 24) & 0xff));
  dst->push_back(static_cast<char>((value >> 16) & 0xff));
  dst->push_back(static_cast<char>((value >> 8) & 0xff));
  dst->push_back(static_cast<char>(value & 0xff));
}

void PushBackUInt32(std::vector<char>* dst, std::uint_fast32_t value) {
  dst->push_back(static_cast<char>((value >> 24) & 0xff));
  dst->push_back(static_cast<char>((value >> 16) & 0xff));
  dst->push_back(static_cast<char>((value >> 8) & 0xff));
  dst->push_back(static_cast<char>(value & 0xff));
}

void PushBackInt64(std::vector<char>* dst, std::int_fast64_t value) {
  dst->push_back(static_cast<char>((value >> 56) & 0xff));
  dst->push_back(static_cast<char>((value >> 48) & 0xff));
  dst->push_back(static_cast<char>((value >> 40) & 0xff));
  dst->push_back(static_cast<char>((value >> 32) & 0xff));
  dst->push_back(static_cast<char>((value >> 24) & 0xff));
  dst->push_back(static_cast<char>((value >> 16) & 0xff));
  dst->push_back(static_cast<char>((value >> 8) & 0xff));
  dst->push_back(static_cast<char>(value & 0xff));
}

void WriteTzHeader(std::vector<char>* dest, char tzh_version,
                   std::uint_fast32_t tzh_timecnt,
                   std::uint_fast32_t tzh_typecnt,
                   std::uint_fast32_t tzh_charcnt) {
  dest->push_back('T');
  dest->push_back('Z');
  dest->push_back('i');
  dest->push_back('f');

  dest->push_back(tzh_version);
  for (size_t i = 0; i < 15; ++i) {
    dest->push_back(0);
  }

  PushBackInt32(dest, 0);  // tzh_ttisutcnt
  PushBackInt32(dest, 0);  // tzh_ttisstdcnt
  PushBackInt32(dest, 0);  // tzh_leapcnt

  PushBackUInt32(dest, tzh_timecnt);
  PushBackUInt32(dest, tzh_typecnt);
  PushBackUInt32(dest, tzh_charcnt);
}

// Factory function implementation
std::unique_ptr<WinZoneInfoSource> CreateWinZoneInfoSourceInternal(
    const WinTimeZoneRegistryInfo& info) {
  const TransitionTable transition_table = TransitionTableBuilder::Build(info);

  const std::vector<Transition>& transitions = transition_table.transitions;
  const std::vector<TransitionType>& types = transition_table.transition_types;
  const std::string abbr_string = transition_table.abbreviation_table;

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
  WriteTzHeader(&data, '2', static_cast<std::uint_fast32_t>(trans32.size()),
                static_cast<std::uint_fast32_t>(types.size()),
                static_cast<std::uint_fast32_t>(abbr_string.size()));

  // Write 32-bit transition times
  for (const auto& trans : trans32) {
    PushBackInt32(&data, static_cast<std::int_fast32_t>(trans.time));
  }

  // Write transition type indices
  for (const auto& trans : trans32) {
    data.push_back(trans.type_idx);
  }

  // Write transition types
  for (const auto& type : types) {
    PushBackInt32(&data, type.offset);
    data.push_back(type.is_dst ? 1 : 0);
    data.push_back(type.abbr_idx);
  }

  // Write abbreviation string
  data.insert(data.end(), abbr_string.begin(), abbr_string.end());

  // No leap seconds, standard/wall indicators, or UTC/local indicators

  // === VERSION 2 SECTION (64-bit) ===
  // Second header
  WriteTzHeader(&data, '2', static_cast<std::uint_fast32_t>(transitions.size()),
                static_cast<std::uint_fast32_t>(types.size()),
                static_cast<std::uint_fast32_t>(abbr_string.size()));

  // Write 64-bit transition times
  for (const auto& trans : transitions) {
    PushBackInt64(&data, trans.time);
  }

  // Write transition type indices
  for (const auto& trans : transitions) {
    data.push_back(trans.type_idx);
  }

  // Write transition types again
  for (const auto& type : types) {
    PushBackInt32(&data, type.offset);
    data.push_back(type.is_dst ? 1 : 0);
    data.push_back(type.abbr_idx);
  }

  // Write abbreviation string again
  data.insert(data.end(), abbr_string.begin(), abbr_string.end());

  // No leap seconds, standard/wall indicators, or UTC/local indicators

  // Append the proleptic TZ string
  data.push_back('\n');
  data.insert(data.end(), transition_table.prolepic_tz_string.begin(),
              transition_table.prolepic_tz_string.end());
  data.push_back('\n');

  return std::make_unique<WinZoneInfoSource>(std::move(data));
}

std::string ToTzAbbrAndOffset(cctz::seconds offset) {
  const auto offset_count = offset.count();
  if (offset_count == 0) {
    return "UTC0";
  }
  const auto offset_min = std::abs((offset_count % 3600) / 60);
  return "<UTC" + cctz::FixedOffsetToAbbr(cctz::seconds(-offset_count)) + ">" +
         std::to_string(offset_count / 3600) +
         (offset_min == 0 ? "" : ":" + std::to_string(offset_min));
}

WinSystemTime AdjustWinSystemTime(const WinSystemTime& system_time) {
  // Special rule for "23:59:59.999".
  // https://stackoverflow.com/a/47106207
  if (system_time.hour == 23 && system_time.minute == 59 &&
      system_time.second == 59 && system_time.milliseconds == 999) {
    const auto new_day_of_week = (system_time.day_of_week + 1) % 7;
    if (new_day_of_week > system_time.day_of_week) {
      const auto new_day = std::min(5, system_time.day + 1);
      return WinSystemTime(system_time.year, system_time.month, new_day_of_week,
                           new_day, 0, 0, 0, 0);
    }
    return WinSystemTime(system_time.year, system_time.month, new_day_of_week,
                         system_time.day, 0, 0, 0, 0);
  }
  return system_time;
}

void Format02d(std::string* str, std::uint_fast8_t v) {
  str->push_back('0' + ((v / 10) % 10));
  str->push_back('0' + (v % 10));
}

void Format01d(std::string* str, std::uint_fast8_t v) {
  if (v >= 10) {
    str->push_back('0' + ((v / 10) % 10));
  }
  str->push_back('0' + (v % 10));
}

std::string ToTzTransitionDateTimeStr(const WinSystemTime& datetime) {
  const auto adjusted_datetime = AdjustWinSystemTime(datetime);
  if (adjusted_datetime.month == 0) {
    return "";
  }

  std::string result;
  result.reserve(sizeof(",Mmm.dd.ww.hh.mm.ss"));

  result.append(",M");
  Format01d(&result, adjusted_datetime.month);
  result.push_back('.');
  Format01d(&result, adjusted_datetime.day);
  result.push_back('.');
  Format01d(&result, adjusted_datetime.day_of_week);
  result.push_back('/');
  Format01d(&result, adjusted_datetime.hour);
  result.push_back(':');
  Format02d(&result, adjusted_datetime.minute);
  result.push_back(':');
  Format02d(&result, adjusted_datetime.second);

  return result;
}

// Construct TZ String Extensions
std::string ToTzStringImpl(const WinTimeZoneRegistryEntry& entry) {
  const std::string std_tz =
      ToTzAbbrAndOffset(cctz::seconds(60 * (entry.bias + entry.standard_bias)));
  if (entry.standard_date.month == 0 && entry.daylight_date.month == 0) {
    return std_tz;
  }
  const std::string dst_tz =
      ToTzAbbrAndOffset(cctz::seconds(60 * (entry.bias + entry.daylight_bias)));
  const std::string dst_start = ToTzTransitionDateTimeStr(entry.daylight_date);
  const std::string std_start = ToTzTransitionDateTimeStr(entry.standard_date);
  return std_tz + dst_tz + dst_start + std_start;
}

}  // namespace

std::unique_ptr<ZoneInfoSource> CreateWinZoneInfoSource(
    const WinTimeZoneRegistryInfo& info) {
  return CreateWinZoneInfoSourceInternal(info);
}

std::string ToTzString(const WinTimeZoneRegistryEntry& entry) {
  return ToTzStringImpl(entry);
}

}  // namespace cctz

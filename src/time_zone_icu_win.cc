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

// USE_WIN32_ICU_TIME_ZONE_APIS will be set only when the following conditions
// are met:
//  * <icu.h> is available.
//  * NTDDI_WIN11_ZN is defined in the Windows SDK.
// https://learn.microsoft.com/en-us/windows/win32/intl/international-components-for-unicode--icu-
// https://devblogs.microsoft.com/oldnewthing/20210527-00/?p=105255
#if defined(_WIN32) && defined(__has_include)
#if __has_include(<icu.h>)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif  // !defined(NOMINMAX)
#include <windows.h>
#if defined(NTDDI_WIN11_ZN)
#pragma push_macro("_WIN32_WINNT")
#pragma push_macro("NTDDI_VERSION")
// Minimum _WIN32_WINNT and NTDDI_VERSION to use ucal_getHostTimeZone
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00  // == _WIN32_WINNT_WIN10
#undef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN11_ZN
#include <icu.h>
#pragma pop_macro("NTDDI_VERSION")
#pragma pop_macro("_WIN32_WINNT")
#define USE_WIN32_ICU_TIME_ZONE_APIS
#endif  // defined(NTDDI_WIN11_ZN)
#endif  // __has_include(<icu.h>)
#endif  // defined(_WIN32) && defined(__has_include)

#include <string>

#if defined(USE_WIN32_ICU_TIME_ZONE_APIS)
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <iostream>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <utility>

#include "time_zone_if.h"

namespace cctz {
namespace {

static std::atomic_bool g_unavailable;

static std::atomic<decltype(&::ucal_clear)> g_ucal_clear;
static std::atomic<decltype(&::ucal_close)> g_ucal_close;
static std::atomic<decltype(&::ucal_get)> g_ucal_get;
static std::atomic<decltype(&::ucal_getCanonicalTimeZoneID)>
    g_ucal_getCanonicalTimeZoneID;
static std::atomic<decltype(&::ucal_getHostTimeZone)> g_ucal_getHostTimeZone;
static std::atomic<decltype(&::ucal_getMillis)> g_ucal_getMillis;
static std::atomic<decltype(&::ucal_getTimeZoneDisplayName)>
    g_ucal_getTimeZoneDisplayName;
static std::atomic<decltype(&::ucal_getTimeZoneIDForWindowsID)>
    g_ucal_getTimeZoneIDForWindowsID;
static std::atomic<decltype(&::ucal_getTimeZoneTransitionDate)>
    g_ucal_getTimeZoneTransitionDate;
static std::atomic<decltype(&::ucal_getTZDataVersion)> g_ucal_getTZDataVersion;
static std::atomic<decltype(&::ucal_inDaylightTime)> g_ucal_inDaylightTime;
static std::atomic<decltype(&::ucal_open)> g_ucal_open;
static std::atomic<decltype(&::ucal_set)> g_ucal_set;
static std::atomic<decltype(&::ucal_setMillis)> g_ucal_setMillis;

using ScopedUCalendar = std::unique_ptr<UCalendar, decltype(&::ucal_close)>;

U_CAPI int32_t U_EXPORT2 ucal_getHostTimeZone_stub(UChar* result,
                                                   int32_t resultCapacity,
                                                   UErrorCode* ec) {
  if (ec != nullptr) {
    *ec = U_UNSUPPORTED_ERROR;
  }
  return 0;
}

struct IcuFunctions {
  bool available;
  decltype(&::ucal_clear) ucal_clear;
  decltype(&::ucal_close) ucal_close;
  decltype(&::ucal_get) ucal_get;
  decltype(&::ucal_getCanonicalTimeZoneID) ucal_getCanonicalTimeZoneID;
  decltype(&::ucal_getHostTimeZone) ucal_getHostTimeZone;
  decltype(&::ucal_getMillis) ucal_getMillis;
  decltype(&::ucal_getTimeZoneDisplayName) ucal_getTimeZoneDisplayName;
  decltype(&::ucal_getTimeZoneIDForWindowsID) ucal_getTimeZoneIDForWindowsID;
  decltype(&::ucal_getTimeZoneTransitionDate) ucal_getTimeZoneTransitionDate;
  decltype(&::ucal_getTZDataVersion) ucal_getTZDataVersion;
  decltype(&::ucal_open) ucal_open;
  decltype(&::ucal_set) ucal_set;
  decltype(&::ucal_setMillis) ucal_setMillis;

  static IcuFunctions Unavailable() {
    return {false,   nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
  }
};

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
  const int num_counts_with_null = num_counts + 1;  // Include null terminator
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

inline UDate ToUDate(const time_point<seconds>& tp) {
  const auto tp_millis =
      std::chrono::time_point_cast<std::chrono::milliseconds>(tp);
  const auto epock_millis =
      std::chrono::time_point_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::from_time_t(0));
  return static_cast<UDate>((tp_millis - epock_millis).count());
}

inline time_point<seconds> FromUData(UDate t) {
  const auto epock_milli =
      std::chrono::time_point_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::from_time_t(0));
  const auto udata_milli = std::chrono::milliseconds(
      static_cast<std::chrono::milliseconds::rep>(std::floor(t)));
  return std::chrono::time_point_cast<seconds>(epock_milli + udata_milli);
}

IcuFunctions GetIcuFunctions() {
  // If we have already failed to load one ore more APIs, then just give up.
  if (g_unavailable.load()) {
    return IcuFunctions::Unavailable();
  }

  {
    const auto ucal_clearRef = g_ucal_clear.load(std::memory_order_relaxed);
    const auto ucal_closeRef = g_ucal_close.load(std::memory_order_relaxed);
    const auto ucal_getRef = g_ucal_get.load(std::memory_order_relaxed);
    const auto ucal_getCanonicalTimeZoneIDRef =
        g_ucal_getCanonicalTimeZoneID.load(std::memory_order_relaxed);
    const auto ucal_getHostTimeZoneRef =
        g_ucal_getHostTimeZone.load(std::memory_order_relaxed);
    const auto ucal_getMillisRef =
        g_ucal_getMillis.load(std::memory_order_relaxed);
    const auto ucal_getTimeZoneDisplayNameRef =
        g_ucal_getTimeZoneDisplayName.load(std::memory_order_relaxed);
    const auto ucal_getTimeZoneIDForWindowsIDRef =
        g_ucal_getTimeZoneIDForWindowsID.load(std::memory_order_relaxed);
    const auto ucal_getTimeZoneTransitionDateRef =
        g_ucal_getTimeZoneTransitionDate.load(std::memory_order_relaxed);
    const auto ucal_getTZDataVersionRef =
        g_ucal_getTZDataVersion.load(std::memory_order_relaxed);
    const auto ucal_openRef = g_ucal_open.load(std::memory_order_relaxed);
    const auto ucal_setRef = g_ucal_set.load(std::memory_order_relaxed);
    const auto ucal_setMillisRef =
        g_ucal_setMillis.load(std::memory_order_relaxed);
    if (ucal_clearRef != nullptr && ucal_closeRef != nullptr &&
        ucal_getRef != nullptr && ucal_getCanonicalTimeZoneIDRef != nullptr &&
        ucal_getHostTimeZoneRef != nullptr && ucal_getMillisRef != nullptr &&
        ucal_getTimeZoneDisplayNameRef != nullptr &&
        ucal_getTimeZoneIDForWindowsIDRef != nullptr &&
        ucal_getTimeZoneTransitionDateRef != nullptr &&
        ucal_getTZDataVersionRef != nullptr && ucal_openRef != nullptr &&
        ucal_setRef != nullptr && ucal_setMillisRef != nullptr) {
      return {true,
              ucal_clearRef,
              ucal_closeRef,
              ucal_getRef,
              ucal_getCanonicalTimeZoneIDRef,
              ucal_getHostTimeZoneRef,
              ucal_getMillisRef,
              ucal_getTimeZoneDisplayNameRef,
              ucal_getTimeZoneIDForWindowsIDRef,
              ucal_getTimeZoneTransitionDateRef,
              ucal_getTZDataVersionRef,
              ucal_openRef,
              ucal_setRef,
              ucal_setMillisRef};
    }
  }

  const HMODULE icudll =
      ::LoadLibraryExW(L"icu.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (icudll == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }

#define GetProcAddressHelper(dll, name) \
  reinterpret_cast<decltype(&::name)>(::GetProcAddress(dll, #name))

  const auto ucal_clearRef = GetProcAddressHelper(icudll, ucal_clear);
  if (ucal_clearRef == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }
  const auto ucal_closeRef = GetProcAddressHelper(icudll, ucal_close);
  if (ucal_closeRef == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }
  const auto ucal_getRef = GetProcAddressHelper(icudll, ucal_get);
  if (ucal_getRef == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }
  auto ucal_getCanonicalTimeZoneIDRef =
      GetProcAddressHelper(icudll, ucal_getCanonicalTimeZoneID);
  if (ucal_getCanonicalTimeZoneIDRef == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }
  auto ucal_getHostTimeZoneRef =
      GetProcAddressHelper(icudll, ucal_getHostTimeZone);
  // `ucal_getHostTimeZone` is available on Windows 11+. So accept `nullptr`.
  if (ucal_getHostTimeZoneRef == nullptr) {
    // Put a stub to keep this field non-null.
    ucal_getHostTimeZoneRef = &ucal_getHostTimeZone_stub;
  }
  const auto ucal_getMillisRef = GetProcAddressHelper(icudll, ucal_getMillis);
  if (ucal_getRef == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }
  const auto ucal_getTimeZoneDisplayNameRef =
      GetProcAddressHelper(icudll, ucal_getTimeZoneDisplayName);
  if (ucal_getTimeZoneDisplayNameRef == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }
  const auto ucal_getTimeZoneIDForWindowsIDRef =
      GetProcAddressHelper(icudll, ucal_getTimeZoneIDForWindowsID);
  if (ucal_getTimeZoneIDForWindowsIDRef == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }
  const auto ucal_getTimeZoneTransitionDateRef =
      GetProcAddressHelper(icudll, ucal_getTimeZoneTransitionDate);
  if (ucal_getTimeZoneTransitionDateRef == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }
  const auto ucal_getTZDataVersionRef =
      GetProcAddressHelper(icudll, ucal_getTZDataVersion);
  if (ucal_getTZDataVersionRef == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }
  const auto ucal_openRef = GetProcAddressHelper(icudll, ucal_open);
  if (ucal_getRef == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }
  const auto ucal_setRef = GetProcAddressHelper(icudll, ucal_set);
  if (ucal_setRef == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }
  const auto ucal_setMillisRef = GetProcAddressHelper(icudll, ucal_setMillis);
  if (ucal_setMillisRef == nullptr) {
    g_unavailable.store(true);
    return IcuFunctions::Unavailable();
  }
#undef GetProcAddressHelper

  g_ucal_clear.store(ucal_clearRef, std::memory_order_relaxed);
  g_ucal_close.store(ucal_closeRef, std::memory_order_relaxed);
  g_ucal_get.store(ucal_getRef, std::memory_order_relaxed);
  g_ucal_getCanonicalTimeZoneID.store(ucal_getCanonicalTimeZoneIDRef,
                                      std::memory_order_relaxed);
  g_ucal_getHostTimeZone.store(ucal_getHostTimeZoneRef,
                               std::memory_order_relaxed);
  g_ucal_getMillis.store(ucal_getMillisRef, std::memory_order_relaxed);
  g_ucal_getTimeZoneDisplayName.store(ucal_getTimeZoneDisplayNameRef,
                                      std::memory_order_relaxed);
  g_ucal_getTimeZoneIDForWindowsID.store(ucal_getTimeZoneIDForWindowsIDRef,
                                         std::memory_order_relaxed);
  g_ucal_getTimeZoneTransitionDate.store(ucal_getTimeZoneTransitionDateRef,
                                         std::memory_order_relaxed);
  g_ucal_getTZDataVersion.store(ucal_getTZDataVersionRef,
                                std::memory_order_relaxed);
  g_ucal_open.store(ucal_openRef, std::memory_order_relaxed);
  g_ucal_set.store(ucal_setRef, std::memory_order_relaxed);
  g_ucal_setMillis.store(ucal_setMillisRef, std::memory_order_relaxed);

  return {true,
          ucal_clearRef,
          ucal_closeRef,
          ucal_getRef,
          ucal_getCanonicalTimeZoneIDRef,
          ucal_getHostTimeZoneRef,
          ucal_getMillisRef,
          ucal_getTimeZoneDisplayNameRef,
          ucal_getTimeZoneIDForWindowsIDRef,
          ucal_getTimeZoneTransitionDateRef,
          ucal_getTZDataVersionRef,
          ucal_openRef,
          ucal_setRef,
          ucal_setMillisRef};
}

struct icu_civil_transition {
  cctz::civil_second from;
  cctz::civil_second to;
  UDate date;
};

struct icu_absolute_lookup {
  cctz::civil_second cs;
  int offset;        // civil seconds east of UTC
  bool is_dst;       // is offset non-standard?
  std::string abbr;  // time-zone abbreviation (e.g., "PST")
};

struct icu_civil_lookup {
  time_zone::civil_lookup::civil_kind kind;
  UDate pre;    // uses the pre-transition offset
  UDate trans;  // instant of civil-offset change
  UDate post;   // uses the post-transition offset
};

const char* MakeStrPermanent(const std::string& str) {
  // This mutex is intentionally "leaked" to avoid the static deinitialization
  static std::mutex* storage_mutex = new std::mutex;

  // This storage is intentionally "leaked" to avoid the static deinitialization
  static auto* storage = new std::unordered_set<std::string>();

  {
    std::lock_guard<std::mutex> lock(*storage_mutex);
    return storage->insert(str).first->c_str();
  }
}

class UCalendarWrapper {
 public:
  UCalendarWrapper() = delete;
  explicit UCalendarWrapper(IcuFunctions icu_functions)
      : functions_(icu_functions), ptr_(nullptr, icu_functions.ucal_close) {}

  bool Open(const std::string& timezone) {
    if (!functions_.available) {
      return false;
    }
    auto zone_id = ToUChars(timezone);
    if (zone_id.second <= 0) {
      return false;
    }
    UErrorCode status = U_ZERO_ERROR;

    int buffer_size = 32;
    std::unique_ptr<UChar[]> buffer = std::make_unique<UChar[]>(buffer_size);

    UBool is_system = false;
    int length = functions_.ucal_getCanonicalTimeZoneID(
        zone_id.first.get(), zone_id.second, buffer.get(), buffer_size,
        &is_system, &status);
    if (status == U_BUFFER_OVERFLOW_ERROR && length > 0) {
      status = U_ZERO_ERROR;
      buffer_size = length + 1;  // +1 for null terminator
      buffer = std::make_unique<UChar[]>(buffer_size);
      length = functions_.ucal_getCanonicalTimeZoneID(
          zone_id.first.get(), zone_id.second, buffer.get(), buffer_size,
          &is_system, &status);
    }
    if (U_FAILURE(status) || length <= 0) {
      return false;
    }

    UCalendar* cal = functions_.ucal_open(zone_id.first.get(), zone_id.second,
                                          nullptr, UCAL_GREGORIAN, &status);
    if (status != U_ZERO_ERROR) {
      return false;
    }
    ptr_.reset(cal);
    return true;
  }

  bool SetMillis(double millis) const {
    if (!functions_.available) {
      return false;
    }
    UErrorCode status = U_ZERO_ERROR;
    functions_.ucal_setMillis(ptr_.get(), millis, &status);
    if (U_FAILURE(status)) {
      return false;
    }
    return true;
  }

  bool GetMillis(double* millis) const {
    if (!functions_.available) {
      return false;
    }
    UErrorCode status = U_ZERO_ERROR;
    *millis = functions_.ucal_getMillis(ptr_.get(), &status);
    return status == U_ZERO_ERROR;
  }

  bool GetTimeZoneTransitionDate(UTimeZoneTransitionType type,
                                 double* transition) {
    if (!functions_.available) {
      return false;
    }
    UErrorCode status = U_ZERO_ERROR;
    UBool result = functions_.ucal_getTimeZoneTransitionDate(
        ptr_.get(), type, transition, &status);
    if (status != U_ZERO_ERROR) {
      return false;
    }
    return result;
  }

  bool GetDateTime(UDate date, cctz::civil_second* local_time,
                   int32_t* local_millisecond) const {
    if (!functions_.available) {
      return false;
    }
    if (!SetMillis(date)) {
      return false;
    }

    UDate date_rounded = 0;
    if (!GetMillis(&date_rounded)) {
      return false;
    }
    if (date_rounded != date) {
      return false;
    }

    UErrorCode status = U_ZERO_ERROR;
    int32_t civil_year = functions_.ucal_get(ptr_.get(), UCAL_YEAR, &status);
    if (status != U_ZERO_ERROR) {
      return false;
    }
    int32_t civil_month =
        functions_.ucal_get(ptr_.get(), UCAL_MONTH, &status) + 1;
    if (status != U_ZERO_ERROR) {
      return false;
    }
    int32_t civil_day =
        functions_.ucal_get(ptr_.get(), UCAL_DAY_OF_MONTH, &status);
    if (status != U_ZERO_ERROR) {
      return false;
    }
    int32_t civil_hour =
        functions_.ucal_get(ptr_.get(), UCAL_HOUR_OF_DAY, &status);
    if (status != U_ZERO_ERROR) {
      return false;
    }
    int32_t civil_minute =
        functions_.ucal_get(ptr_.get(), UCAL_MINUTE, &status);
    if (status != U_ZERO_ERROR) {
      return false;
    }
    int32_t civil_second =
        functions_.ucal_get(ptr_.get(), UCAL_SECOND, &status);
    if (status != U_ZERO_ERROR) {
      return false;
    }
    if (local_millisecond != nullptr) {
      int32_t civil_millisecond =
          functions_.ucal_get(ptr_.get(), UCAL_MILLISECOND, &status);
      if (status != U_ZERO_ERROR) {
        return false;
      }
      *local_millisecond = civil_millisecond;
    }
    *local_time = cctz::civil_second(civil_year, civil_month, civil_day,
                                     civil_hour, civil_minute, civil_second);
    return true;
  }

  bool NextTransition(UDate date, icu_civil_transition* trans) const {
    if (!functions_.available) {
      return false;
    }
    if (!SetMillis(date)) {
      return false;
    }

    UDate date_rounded = 0;
    if (!GetMillis(&date_rounded)) {
      return false;
    }
    if (date_rounded < date) {
      return false;
    }

    UDate transition = 0;
    UErrorCode status = U_ZERO_ERROR;
    UBool result = functions_.ucal_getTimeZoneTransitionDate(
        ptr_.get(), UCAL_TZ_TRANSITION_NEXT_INCLUSIVE, &transition, &status);
    if (!result || U_FAILURE(status)) {
      return false;
    }
    if (transition == date) {
      return false;
    }

    int32_t transition_millisecond_from = 0;
    cctz::civil_second transition_localtime_from;
    if (!GetDateTime(transition - 1, &transition_localtime_from,
                     &transition_millisecond_from)) {
      return false;
    }
    if (transition_millisecond_from == 999) {
      transition_localtime_from += 1;
    }
    int32_t transition_millisecond_to = 0;
    cctz::civil_second transition_localtime_to;
    if (!GetDateTime(transition, &transition_localtime_to,
                     &transition_millisecond_to)) {
      return false;
    }
    trans->from = transition_localtime_from;
    trans->to = transition_localtime_to;
    return true;
  }

  bool PrevTransition(UDate date, icu_civil_transition* trans) const {
    if (!functions_.available) {
      return false;
    }
    if (!SetMillis(date)) {
      return false;
    }

    UDate date_rounded = 0;
    if (!GetMillis(&date_rounded)) {
      return false;
    }
    if (date < date_rounded) {
      return false;
    }

    UDate transition = 0;
    UErrorCode status = U_ZERO_ERROR;
    UBool result = functions_.ucal_getTimeZoneTransitionDate(
        ptr_.get(), UCAL_TZ_TRANSITION_PREVIOUS_INCLUSIVE, &transition,
        &status);
    if (!result || U_FAILURE(status)) {
      return false;
    }
    if (transition == date) {
      return false;
    }

    int32_t transition_millisecond_from = 0;
    cctz::civil_second transition_localtime_from;
    if (!GetDateTime(transition - 1, &transition_localtime_from,
                     &transition_millisecond_from)) {
      return false;
    }
    if (transition_millisecond_from == 999) {
      transition_localtime_from += 1;
    }
    int32_t transition_millisecond_to = 0;
    cctz::civil_second transition_localtime_to;
    if (!GetDateTime(transition, &transition_localtime_to,
                     &transition_millisecond_to)) {
      return false;
    }
    trans->from = transition_localtime_from;
    trans->to = transition_localtime_to;
    trans->date = transition;
    return true;
  }

  const char* GetTZDataVersion() const {
    UErrorCode status = U_ZERO_ERROR;
    const char* version = functions_.ucal_getTZDataVersion(&status);
    if (U_FAILURE(status) || version == nullptr) {
      return "";
    }
    return version;
  }

  std::string GetAbbr(bool is_dst) const {
    if (!functions_.available) {
      return "";
    }
    UErrorCode status = U_ZERO_ERROR;

    const UCalendarDisplayNameType type =
        is_dst ? UCalendarDisplayNameType::UCAL_SHORT_DST
               : UCalendarDisplayNameType::UCAL_SHORT_STANDARD;
    int buffer_size = 16;
    std::unique_ptr<UChar[]> buffer = std::make_unique<UChar[]>(buffer_size);

    int length = functions_.ucal_getTimeZoneDisplayName(
        ptr_.get(), type, nullptr, buffer.get(), buffer_size, &status);
    if (status == U_BUFFER_OVERFLOW_ERROR && length > 0) {
      status = U_ZERO_ERROR;
      buffer_size = length + 1;  // +1 for null terminator
      buffer = std::make_unique<UChar[]>(buffer_size);
      length = functions_.ucal_getTimeZoneDisplayName(
          ptr_.get(), type, nullptr, buffer.get(), buffer_size, &status);
    }
    if (U_FAILURE(status) || length <= 0) {
      return "";
    }
    return FromUChars(buffer.get(), length);
  }

  bool BreakTime(UDate date, icu_absolute_lookup* lookup_result) const {
    cctz::civil_second local_time;
    if (!GetDateTime(date, &local_time, nullptr)) {
      return false;
    }
    UErrorCode status = U_ZERO_ERROR;
    int32_t offset_milli = functions_.ucal_get(ptr_.get(), UCAL_ZONE_OFFSET, &status);
    if (U_FAILURE(status)) {
      return false;
    }
    int32_t dst_offset_milli =
        functions_.ucal_get(ptr_.get(), UCAL_DST_OFFSET, &status);
    if (U_FAILURE(status)) {
      return false;
    }
    offset_milli += dst_offset_milli;
    const bool is_dst = dst_offset_milli != 0;

    lookup_result->cs = local_time;
    lookup_result->is_dst = is_dst;
    lookup_result->abbr = GetAbbr(is_dst);
    lookup_result->offset = static_cast<int>(std::floor(offset_milli / 1000.0));
    return true;
  }

  bool MakeTime(cctz::civil_second local_time,
                icu_civil_lookup* lookup_result) const {
    if (!functions_.available) {
      return false;
    }
    UCalendar* cal = ptr_.get();
    UErrorCode status = U_ZERO_ERROR;
    if (local_time.year() > std::numeric_limits<std::int32_t>::max()) {
      return false;
    }

    const int32_t local_year = static_cast<int32_t>(local_time.year());
    functions_.ucal_clear(cal);
    functions_.ucal_set(cal, UCAL_YEAR, local_year);
    functions_.ucal_set(cal, UCAL_MONTH, local_time.month() - 1);
    functions_.ucal_set(cal, UCAL_DATE, local_time.day());
    functions_.ucal_set(cal, UCAL_HOUR, local_time.hour());
    functions_.ucal_set(cal, UCAL_MINUTE, local_time.minute());
    functions_.ucal_set(cal, UCAL_SECOND, local_time.second());
    functions_.ucal_set(cal, UCAL_MILLISECOND, 0);
    UDate date = functions_.ucal_getMillis(cal, &status);
    functions_.ucal_clear(cal);
    if (!U_SUCCESS(status)) {
      return false;
    }

    icu_civil_transition prev_transition;
    if (!PrevTransition(date, &prev_transition)) {
      lookup_result->kind = time_zone::civil_lookup::UNIQUE;
      lookup_result->pre = date;
      lookup_result->trans = date;
      lookup_result->post = date;
      return true;
    }

    if ((prev_transition.from < prev_transition.to &&
         prev_transition.to <= local_time) ||
        (prev_transition.to < prev_transition.from &&
         prev_transition.from <= local_time)) {
      lookup_result->kind = time_zone::civil_lookup::UNIQUE;
      lookup_result->pre = date;
      lookup_result->trans = date;
      lookup_result->post = date;
      return true;
    }

    if (prev_transition.from <= local_time && local_time < prev_transition.to) {
      lookup_result->kind = time_zone::civil_lookup::SKIPPED;
      lookup_result->pre = date;
      lookup_result->trans = prev_transition.date;
      lookup_result->post =
          date - (prev_transition.to - prev_transition.from) * 1000;
      return true;
    }
    // assert(prev_transition.to <= local_time && local_time <
    // prev_transition.from)
    lookup_result->kind = time_zone::civil_lookup::REPEATED;
    lookup_result->pre =
        date - (prev_transition.from - prev_transition.to) * 1000;
    lookup_result->trans = prev_transition.date;
    lookup_result->post = date;
    return true;
  }

 private:
  ScopedUCalendar ptr_;
  IcuFunctions functions_;
};

class TimeZoneIcuWin : public TimeZoneIf {
 public:
  static std::unique_ptr<TimeZoneIf> Create(const std::string& name) {
    std::unique_ptr<TimeZoneIcuWin> ptr(new TimeZoneIcuWin());
    if (!ptr->cal_.Open(name)) {
      return nullptr;
    }
    return std::unique_ptr<TimeZoneIf>(ptr.release());
  }

  // TimeZoneIf implementations.
  time_zone::absolute_lookup BreakTime(
      const time_point<seconds>& tp) const override {
    time_zone::absolute_lookup result;

    icu_absolute_lookup lookup;
    if (!cal_.BreakTime(ToUDate(tp), &lookup)) {
      return result;
    }

    result.cs = lookup.cs;
    result.is_dst = lookup.is_dst;
    result.offset = lookup.offset;
    result.abbr = MakeStrPermanent(lookup.abbr);
    return result;
  }

  time_zone::civil_lookup MakeTime(const civil_second& cs) const override {
    icu_civil_lookup lookup;
    time_zone::civil_lookup result;
    if (cal_.MakeTime(cs, &lookup)) {
      result.kind = lookup.kind;
      result.pre = FromUData(lookup.pre);
      result.trans = FromUData(lookup.trans);
      result.post = FromUData(lookup.post);
    }
    return result;
  }

  bool NextTransition(const time_point<seconds>& tp,
                      time_zone::civil_transition* trans) const override {
    icu_civil_transition transition;
    if (!cal_.NextTransition(tp.time_since_epoch().count() * 1000.0,
                             &transition)) {
      return false;
    }
    trans->from = transition.from;
    trans->to = transition.to;
    return true;
  }

  bool PrevTransition(const time_point<seconds>& tp,
                      time_zone::civil_transition* trans) const override {
    icu_civil_transition transition;
    if (!cal_.PrevTransition(tp.time_since_epoch().count() * 1000.0,
                             &transition)) {
      return false;
    }
    trans->from = transition.from;
    trans->to = transition.to;
    return true;
  }

  std::string Version() const override { return cal_.GetTZDataVersion(); }
  std::string Description() const override { return ""; }

 private:
  explicit TimeZoneIcuWin() : cal_(GetIcuFunctions()) {
  }

  TimeZoneIcuWin(const TimeZoneIcuWin&) = delete;
  TimeZoneIcuWin& operator=(const TimeZoneIcuWin&) = delete;
  UCalendarWrapper cal_;
};

}  // namespace

std::string win32_local_time_zone() {
  const auto icu_funcs = GetIcuFunctions();
  if (!icu_funcs.available) {
    return "";
  }
  if (icu_funcs.ucal_getHostTimeZone != &ucal_getHostTimeZone_stub) {
    int buffer_size = 256;
    std::unique_ptr<UChar[]> buffer = std::make_unique<UChar[]>(buffer_size);
    UErrorCode status = U_ZERO_ERROR;
    int32_t length =
        icu_funcs.ucal_getHostTimeZone(buffer.get(), buffer_size, &status);
    if (status == U_BUFFER_OVERFLOW_ERROR && length > 0) {
      status = U_ZERO_ERROR;
      buffer_size = length + 1;  // +1 for null terminator
      buffer = std::make_unique<UChar[]>(buffer_size);
      length =
          icu_funcs.ucal_getHostTimeZone(buffer.get(), buffer_size, &status);
    }
    if (U_FAILURE(status) || length <= 0) {
      return "";
    }
    return FromUChars(buffer.get(), length);
  }

  UErrorCode status = U_ZERO_ERROR;
  DYNAMIC_TIME_ZONE_INFORMATION info = {};
  if (::GetDynamicTimeZoneInformation(&info) == TIME_ZONE_ID_INVALID) {
    return "";
  }

  int buffer_size = 256;
  std::unique_ptr<UChar[]> buffer = std::make_unique<UChar[]>(buffer_size);

  int32_t length = icu_funcs.ucal_getTimeZoneIDForWindowsID(
      reinterpret_cast<const UChar*>(info.TimeZoneKeyName), -1, nullptr,
      buffer.get(), buffer_size, &status);
  if (status == U_BUFFER_OVERFLOW_ERROR && length > 0) {
    status = U_ZERO_ERROR;
    buffer_size = length + 1;  // +1 for null terminator
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

std::unique_ptr<TimeZoneIf> MakeWin32TimeZone(const std::string& name) {
  return TimeZoneIcuWin::Create(name);
}

}  // namespace cctz

#else  // !defined(USE_WIN32_ICU_TIME_ZONE_APIS)

namespace cctz {

std::string win32_local_time_zone() { return ""; }

std::unique_ptr<TimeZoneIf> MakeWin32TimeZone(const std::string& name) {
  return nullptr;
}

}  // namespace cctz

#endif  // defined(USE_WIN32_ICU_TIME_ZONE_APIS)

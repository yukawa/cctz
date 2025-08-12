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

#include <atomic>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "time_zone_if.h"

namespace cctz {
namespace {

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

enum UCalendarDateFields : int32_t {
  UCAL_YEAR = 1,
  UCAL_MONTH = 2,
  UCAL_DAY_OF_MONTH = 5,  // == UCAL_DATE
  UCAL_HOUR = 10,
  UCAL_HOUR_OF_DAY = 11,
  UCAL_MINUTE = 12,
  UCAL_SECOND = 13,
  UCAL_MILLISECOND = 14,
  UCAL_ZONE_OFFSET = 15,
  UCAL_DST_OFFSET = 16,
};

enum UCalendarType : int32_t {
  UCAL_GREGORIAN = 0,
};

enum UCalendarDisplayNameType : int32_t {
  UCAL_SHORT_STANDARD = 1,
  UCAL_SHORT_DST = 3,
};

enum UTimeZoneTransitionType : int32_t {
  UCAL_TZ_TRANSITION_NEXT = 0,
  UCAL_TZ_TRANSITION_NEXT_INCLUSIVE = 1,
  UCAL_TZ_TRANSITION_PREVIOUS_INCLUSIVE = 3,
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
  using ucal_clear_func = void(__cdecl*)(UCalendar* cal);
  using ucal_clone_func = UCalendar*(__cdecl*)(const UCalendar* cal,
                                               UErrorCode* status);
  using ucal_close_func = void(__cdecl*)(UCalendar* cal);
  using ucal_get_func = int32_t(__cdecl*)(const UCalendar* cal,
                                          UCalendarDateFields field,
                                          UErrorCode* status);
  using ucal_getCanonicalTimeZoneID_func = int32_t(__cdecl*)(
      const UChar* id, int32_t len, UChar* result, int32_t resultCapacity,
      UBool* isSystemID, UErrorCode* status);
  using ucal_getTimeZoneDisplayName_func = int32_t(__cdecl*)(
      const UCalendar* cal, UCalendarDisplayNameType type, const char* locale,
      UChar* result, int32_t resultLength, UErrorCode* status);
  using ucal_getTimeZoneTransitionDate_func =
      UBool(__cdecl*)(const UCalendar* cal, UTimeZoneTransitionType type,
                      UDate* transition, UErrorCode* status);
  using ucal_getTZDataVersion_func = const char*(__cdecl*)(UErrorCode* status);
  using ucal_open_func = UCalendar*(__cdecl*)(const UChar* zoneID, int32_t len,
                                              const char* locale,
                                              UCalendarType caltype,
                                              UErrorCode* status);
  using ucal_set_func = void(__cdecl*)(UCalendar* cal,
                                       UCalendarDateFields field,
                                       int32_t value);
  using ucal_setMillis_func = void(__cdecl*)(UCalendar* cal, UDate dateTime,
                                             UErrorCode* status);
  using ucal_getMillis_func = UDate(__cdecl*)(const UCalendar* cal,
                                              UErrorCode* status);
  using ucal_getHostTimeZone_func = int32_t(__cdecl*)(UChar* result,
                                                      int32_t resultCapacity,
                                                      UErrorCode* status);
  using ucal_getTimeZoneIDForWindowsID_func =
      int32_t(__cdecl*)(const UChar* winid, int32_t len, const char* region,
                        UChar* id, int32_t idCapacity, UErrorCode* status);

  using ScopedUCalendar = std::unique_ptr<UCalendar, ucal_close_func>;

  const bool available;
  const ucal_clear_func ucal_clear;
  const ucal_clone_func ucal_clone;
  const ucal_close_func ucal_close;
  const ucal_get_func ucal_get;
  const ucal_getCanonicalTimeZoneID_func ucal_getCanonicalTimeZoneID;
  const ucal_getTimeZoneDisplayName_func ucal_getTimeZoneDisplayName;
  const ucal_getTimeZoneTransitionDate_func ucal_getTimeZoneTransitionDate;
  const ucal_getTZDataVersion_func ucal_getTZDataVersion;
  const ucal_open_func ucal_open;
  const ucal_set_func ucal_set;
  const ucal_setMillis_func ucal_setMillis;
  const ucal_getMillis_func ucal_getMillis;
  const ucal_getHostTimeZone_func ucal_getHostTimeZone;
  const ucal_getTimeZoneIDForWindowsID_func ucal_getTimeZoneIDForWindowsID;

  static IcuFunctions Unavailable() {
    return {false,   nullptr, nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr};
  }

  static IcuFunctions Get() {
    static std::atomic<bool> g_unavailable;
    if (g_unavailable.load(std::memory_order_relaxed)) {
      return IcuFunctions::Unavailable();
    }

    static std::atomic<ucal_clear_func> g_ucal_clear;
    static std::atomic<ucal_clone_func> g_ucal_clone;
    static std::atomic<ucal_close_func> g_ucal_close;
    static std::atomic<ucal_get_func> g_ucal_get;
    static std::atomic<ucal_getCanonicalTimeZoneID_func>
        g_ucal_getCanonicalTimeZoneID;
    static std::atomic<ucal_getTimeZoneDisplayName_func>
        g_ucal_getTimeZoneDisplayName;
    static std::atomic<ucal_getTimeZoneTransitionDate_func>
        g_ucal_getTimeZoneTransitionDate;
    static std::atomic<ucal_getTZDataVersion_func> g_ucal_getTZDataVersion;
    static std::atomic<ucal_open_func> g_ucal_open;
    static std::atomic<ucal_set_func> g_ucal_set;
    static std::atomic<ucal_setMillis_func> g_ucal_setMillis;
    static std::atomic<ucal_getMillis_func> g_ucal_getMillis;
    static std::atomic<ucal_getHostTimeZone_func> g_ucal_getHostTimeZone;
    static std::atomic<ucal_getTimeZoneIDForWindowsID_func>
        g_ucal_getTimeZoneIDForWindowsID;

    // Check if already loaded
    {
      const auto ucal_clearRef = g_ucal_clear.load(std::memory_order_relaxed);
      const auto ucal_cloneRef = g_ucal_clone.load(std::memory_order_relaxed);
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
      const auto ucal_setRef = g_ucal_set.load(std::memory_order_relaxed);
      const auto ucal_setMillisRef =
          g_ucal_setMillis.load(std::memory_order_relaxed);
      const auto ucal_getMillisRef =
          g_ucal_getMillis.load(std::memory_order_relaxed);
      const auto ucal_getHostTimeZoneRef =
          g_ucal_getHostTimeZone.load(std::memory_order_relaxed);
      const auto ucal_getTimeZoneIDForWindowsIDRef =
          g_ucal_getTimeZoneIDForWindowsID.load(std::memory_order_relaxed);

      if (ucal_clearRef != nullptr && ucal_closeRef != nullptr &&
          ucal_cloneRef != nullptr && ucal_getRef != nullptr &&
          ucal_getCanonicalTimeZoneIDRef != nullptr &&
          ucal_getTimeZoneDisplayNameRef != nullptr &&
          ucal_getTimeZoneTransitionDateRef != nullptr &&
          ucal_getTZDataVersionRef != nullptr && ucal_openRef != nullptr &&
          ucal_setRef != nullptr && ucal_setMillisRef != nullptr &&
          ucal_getMillisRef != nullptr && ucal_getHostTimeZoneRef != nullptr &&
          ucal_getTimeZoneIDForWindowsIDRef != nullptr) {
        return {true,
                ucal_clearRef,
                ucal_cloneRef,
                ucal_closeRef,
                ucal_getRef,
                ucal_getCanonicalTimeZoneIDRef,
                ucal_getTimeZoneDisplayNameRef,
                ucal_getTimeZoneTransitionDateRef,
                ucal_getTZDataVersionRef,
                ucal_openRef,
                ucal_setRef,
                ucal_setMillisRef,
                ucal_getMillisRef,
                ucal_getHostTimeZoneRef,
                ucal_getTimeZoneIDForWindowsIDRef};
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

    const auto ucal_clearRef =
        AsProcAddress<ucal_clear_func>(icu_dll, "ucal_clear");
    const auto ucal_cloneRef =
        AsProcAddress<ucal_clone_func>(icu_dll, "ucal_clone");
    const auto ucal_closeRef =
        AsProcAddress<ucal_close_func>(icu_dll, "ucal_close");
    const auto ucal_getRef = AsProcAddress<ucal_get_func>(icu_dll, "ucal_get");
    const auto ucal_getCanonicalTimeZoneIDRef =
        AsProcAddress<ucal_getCanonicalTimeZoneID_func>(
            icu_dll, "ucal_getCanonicalTimeZoneID");
    const auto ucal_getTimeZoneDisplayNameRef =
        AsProcAddress<ucal_getTimeZoneDisplayName_func>(
            icu_dll, "ucal_getTimeZoneDisplayName");
    const auto ucal_getTimeZoneTransitionDateRef =
        AsProcAddress<ucal_getTimeZoneTransitionDate_func>(
            icu_dll, "ucal_getTimeZoneTransitionDate");
    const auto ucal_getTZDataVersionRef =
        AsProcAddress<ucal_getTZDataVersion_func>(icu_dll,
                                                  "ucal_getTZDataVersion");
    const auto ucal_openRef =
        AsProcAddress<ucal_open_func>(icu_dll, "ucal_open");
    const auto ucal_setRef = AsProcAddress<ucal_set_func>(icu_dll, "ucal_set");
    const auto ucal_setMillisRef =
        AsProcAddress<ucal_setMillis_func>(icu_dll, "ucal_setMillis");
    const auto ucal_getMillisRef =
        AsProcAddress<ucal_getMillis_func>(icu_dll, "ucal_getMillis");
    auto ucal_getHostTimeZoneRef = AsProcAddress<ucal_getHostTimeZone_func>(
        icu_dll, "ucal_getHostTimeZone");
    const auto ucal_getTimeZoneIDForWindowsIDRef =
        AsProcAddress<ucal_getTimeZoneIDForWindowsID_func>(
            icu_dll, "ucal_getTimeZoneIDForWindowsID");

    if (!ucal_getHostTimeZoneRef) {
      // Note: ucal_getHostTimeZone can be unavailable on older Windows.
      ucal_getHostTimeZoneRef = ucal_getHostTimeZone_stub;
    }

    if (!ucal_clearRef || !ucal_cloneRef || !ucal_closeRef || !ucal_getRef ||
        !ucal_getCanonicalTimeZoneIDRef || !ucal_getTimeZoneDisplayNameRef ||
        !ucal_getTimeZoneTransitionDateRef || !ucal_getTZDataVersionRef ||
        !ucal_openRef || !ucal_setRef || !ucal_setMillisRef ||
        !ucal_getMillisRef || !ucal_getTimeZoneIDForWindowsIDRef) {
      g_unavailable.store(true, std::memory_order_relaxed);
      return IcuFunctions::Unavailable();
    }

    // Store the function pointers
    g_ucal_clear.store(ucal_clearRef, std::memory_order_relaxed);
    g_ucal_clone.store(ucal_cloneRef, std::memory_order_relaxed);
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
    g_ucal_set.store(ucal_setRef, std::memory_order_relaxed);
    g_ucal_setMillis.store(ucal_setMillisRef, std::memory_order_relaxed);
    g_ucal_getMillis.store(ucal_getMillisRef, std::memory_order_relaxed);
    g_ucal_getHostTimeZone.store(ucal_getHostTimeZoneRef,
                                 std::memory_order_relaxed);
    g_ucal_getTimeZoneIDForWindowsID.store(ucal_getTimeZoneIDForWindowsIDRef,
                                           std::memory_order_relaxed);

    return {true,
            ucal_clearRef,
            ucal_cloneRef,
            ucal_closeRef,
            ucal_getRef,
            ucal_getCanonicalTimeZoneIDRef,
            ucal_getTimeZoneDisplayNameRef,
            ucal_getTimeZoneTransitionDateRef,
            ucal_getTZDataVersionRef,
            ucal_openRef,
            ucal_setRef,
            ucal_setMillisRef,
            ucal_getMillisRef,
            ucal_getHostTimeZoneRef,
            ucal_getTimeZoneIDForWindowsIDRef};
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

  auto ustr = std::make_unique<UChar[]>(num_counts);
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
  auto buffer = std::make_unique<char[]>(num_bytes_in_utf8);
  const int num_written_bytes =
      ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, ptr, chars_len,
                            buffer.get(), num_bytes_in_utf8, nullptr, nullptr);
  if (num_written_bytes != num_bytes_in_utf8) {
    return std::string();
  }
  return std::string(buffer.get(), num_written_bytes);
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

struct icu_civil_transition final {
  cctz::civil_second from;
  cctz::civil_second to;
  UDate date;
};

struct icu_absolute_lookup final {
  cctz::civil_second cs;
  int offset;        // civil seconds east of UTC
  bool is_dst;       // is offset non-standard?
  std::string abbr;  // time-zone abbreviation (e.g., "PST")
};

struct icu_civil_lookup final {
  time_zone::civil_lookup::civil_kind kind;
  UDate pre;    // uses the pre-transition offset
  UDate trans;  // instant of civil-offset change
  UDate post;   // uses the post-transition offset
};

class ShortStringPool final {
 public:
  ShortStringPool() : lock_free_thread_id_(::GetCurrentThreadId()) {}

  ShortStringPool(const ShortStringPool&) = delete;
  ShortStringPool(ShortStringPool&&) = delete;
  ShortStringPool& operator=(const ShortStringPool&) = delete;

  ~ShortStringPool() {
#if defined(_DEBUG)
    assert(::GetCurrentThreadId() == lock_free_thread_id_);
#endif
    for (const char* str : lock_free_storage_) {
      delete[] str;
    }
    lock_free_storage_.clear();

    if (storage_used_.load(std::memory_order_acquire)) {
      std::lock_guard<std::mutex> lock(mutex_);
      for (const char* str : storage_) {
        delete[] str;
      }
      storage_.clear();
    }
  }

  const char* Intern(const std::string& str) {
    const size_t str_size = str.size();
    if (str_size > std::numeric_limits<uint8_t>::max()) {
      return nullptr;
    }
    const uint8_t str_size_u8 = static_cast<uint8_t>(str_size);

    // Fast-path for the lock-free thread.
    if (::GetCurrentThreadId() == lock_free_thread_id_) {
      return InternInternal(lock_free_storage_, str.c_str(), str_size_u8);
    }

    // Slow-path for other threads.
    std::lock_guard<std::mutex> lock(mutex_);
    if (storage_.empty()) {
      storage_used_.store(true, std::memory_order_release);
    }
    return InternInternal(storage_, str.c_str(), str_size_u8);
  }

 private:
  static const char* InternInternal(std::vector<const char*>& storage,
                                    const char* str, uint8_t str_size) {
    for (const char* item : storage) {
      uint8_t item_size = 0;
      // TODO: Use std::bit_cast on C++20 or later.
      std::memcpy(&item_size, item, sizeof(item_size));
      const char* item_ptr = item + 1;
      if (str_size != item_size) {
        continue;
      }
      if (std::equal(str, str + str_size, item_ptr)) {
        return item_ptr;
      }
    }
    // +1 for size, +1 for null terminator
    char* new_item = new char[str_size + 1 + 1];
    // TODO: Use std::bit_cast on C++20 or later.
    std::memcpy(new_item, &str_size, sizeof(str_size));
    char* new_item_str = new_item + 1;
    std::copy_n(str, str_size, new_item_str);
    new_item_str[str_size] = '\0';
    storage.push_back(new_item);
    return new_item_str;
  }

  std::vector<const char*> storage_;
  std::mutex mutex_;
  std::atomic<bool> storage_used_;

  std::vector<const char*> lock_free_storage_;
  const DWORD lock_free_thread_id_;
};

// This object may have references to UCalendarOperationFactory fields. Thus its
// lifetime must not be extended beyond the factory's lifetime.
class ThreadLocalUCalendarOperation final {
 public:
  ThreadLocalUCalendarOperation() = delete;
  ThreadLocalUCalendarOperation(const ThreadLocalUCalendarOperation&) = delete;

  // Necessary for C++14, where the copy elision is not guaranteed.
  ThreadLocalUCalendarOperation(ThreadLocalUCalendarOperation&& source) noexcept
      : ptr_(source.ptr_), cache_ptr_(source.cache_ptr_), icu_(source.icu_) {
    source.ptr_ = nullptr;
    source.cache_ptr_ = nullptr;
  }

  ThreadLocalUCalendarOperation& operator=(
      const ThreadLocalUCalendarOperation&) = delete;

  ThreadLocalUCalendarOperation(UCalendar* cal, const IcuFunctions& icu)
      : ptr_(cal), cache_ptr_(nullptr), icu_(icu) {}
  ThreadLocalUCalendarOperation(UCalendar* cal, UCalendar** cache_ptr,
                                const IcuFunctions& icu)
      : ptr_(cal), cache_ptr_(cache_ptr), icu_(icu) {}

  ~ThreadLocalUCalendarOperation() {
    if (ptr_ == nullptr) {
      return;
    }
    if (cache_ptr_ != nullptr && *cache_ptr_ == nullptr) {
      *cache_ptr_ = ptr_;
    } else {
      icu_.ucal_close(ptr_);
    }
  }

  bool NextTransition(UDate date, icu_civil_transition* trans) {
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
    UBool result = icu_.ucal_getTimeZoneTransitionDate(
        ptr_, UCAL_TZ_TRANSITION_NEXT_INCLUSIVE, &transition, &status);
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

  bool PrevTransition(UDate date, icu_civil_transition* trans) {
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
    UBool result = icu_.ucal_getTimeZoneTransitionDate(
        ptr_, UCAL_TZ_TRANSITION_PREVIOUS_INCLUSIVE, &transition, &status);
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

  bool BreakTime(UDate date, icu_absolute_lookup* lookup_result) {
    cctz::civil_second local_time;
    if (!GetDateTime(date, &local_time, nullptr)) {
      return false;
    }
    UErrorCode status = U_ZERO_ERROR;
    int32_t offset_milli = icu_.ucal_get(ptr_, UCAL_ZONE_OFFSET, &status);
    if (U_FAILURE(status)) {
      return false;
    }
    status = U_ZERO_ERROR;
    int32_t dst_offset_milli = icu_.ucal_get(ptr_, UCAL_DST_OFFSET, &status);
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
                icu_civil_lookup* lookup_result) {
    UErrorCode status = U_ZERO_ERROR;
    if (local_time.year() > std::numeric_limits<std::int32_t>::max()) {
      return false;
    }

    const int32_t local_year = static_cast<int32_t>(local_time.year());
    icu_.ucal_clear(ptr_);
    icu_.ucal_set(ptr_, UCAL_YEAR, local_year);
    icu_.ucal_set(ptr_, UCAL_MONTH, local_time.month() - 1);
    icu_.ucal_set(ptr_, UCAL_DAY_OF_MONTH, local_time.day());
    icu_.ucal_set(ptr_, UCAL_HOUR, local_time.hour());
    icu_.ucal_set(ptr_, UCAL_MINUTE, local_time.minute());
    icu_.ucal_set(ptr_, UCAL_SECOND, local_time.second());
    icu_.ucal_set(ptr_, UCAL_MILLISECOND, 0);
    UDate date = icu_.ucal_getMillis(ptr_, &status);
    icu_.ucal_clear(ptr_);
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

#if defined(_DEBUG)
    assert(prev_transition.to <= local_time);
    assert(local_time < prev_transition.from);
#endif

    lookup_result->kind = time_zone::civil_lookup::REPEATED;
    lookup_result->pre =
        date - (prev_transition.from - prev_transition.to) * 1000;
    lookup_result->trans = prev_transition.date;
    lookup_result->post = date;
    return true;
  }

 private:
  bool SetMillis(double millis) {
    UErrorCode status = U_ZERO_ERROR;
    icu_.ucal_setMillis(ptr_, millis, &status);
    if (U_FAILURE(status)) {
      return false;
    }
    return true;
  }

  bool GetMillis(double* millis) {
    UErrorCode status = U_ZERO_ERROR;
    *millis = icu_.ucal_getMillis(ptr_, &status);
    return U_SUCCESS(status);
  }

  bool GetDateTime(UDate date, cctz::civil_second* local_time,
                   int32_t* local_millisecond) {
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
    const int32_t civil_year = icu_.ucal_get(ptr_, UCAL_YEAR, &status);
    if (U_FAILURE(status)) {
      return false;
    }
    status = U_ZERO_ERROR;
    const int32_t civil_month = icu_.ucal_get(ptr_, UCAL_MONTH, &status) + 1;
    if (U_FAILURE(status)) {
      return false;
    }
    status = U_ZERO_ERROR;
    const int32_t civil_day = icu_.ucal_get(ptr_, UCAL_DAY_OF_MONTH, &status);
    if (U_FAILURE(status)) {
      return false;
    }
    status = U_ZERO_ERROR;
    const int32_t civil_hour = icu_.ucal_get(ptr_, UCAL_HOUR_OF_DAY, &status);
    if (U_FAILURE(status)) {
      return false;
    }
    status = U_ZERO_ERROR;
    const int32_t civil_minute = icu_.ucal_get(ptr_, UCAL_MINUTE, &status);
    if (U_FAILURE(status)) {
      return false;
    }
    status = U_ZERO_ERROR;
    const int32_t civil_second = icu_.ucal_get(ptr_, UCAL_SECOND, &status);
    if (U_FAILURE(status)) {
      return false;
    }
    if (local_millisecond != nullptr) {
      status = U_ZERO_ERROR;
      const int32_t civil_millisecond =
          icu_.ucal_get(ptr_, UCAL_MILLISECOND, &status);
      if (U_FAILURE(status)) {
        return false;
      }
      *local_millisecond = civil_millisecond;
    }
    *local_time = cctz::civil_second(civil_year, civil_month, civil_day,
                                     civil_hour, civil_minute, civil_second);
    return true;
  }

  std::string GetAbbr(bool is_dst) const {
    UErrorCode status = U_ZERO_ERROR;

    const UCalendarDisplayNameType type =
        is_dst ? UCalendarDisplayNameType::UCAL_SHORT_DST
               : UCalendarDisplayNameType::UCAL_SHORT_STANDARD;
    int length = 0;
    {
      const int buffer_size = 16;
      UChar buffer[buffer_size];
      length = icu_.ucal_getTimeZoneDisplayName(ptr_, type, nullptr, buffer,
                                                buffer_size, &status);
      if (U_SUCCESS(status) && 0 < length && length <= buffer_size) {
        return Utf16ToUtf8(buffer, length);
      }
      if (status != U_BUFFER_OVERFLOW_ERROR || length <= 0) {
        return std::string();
      }
    }

    const int buffer_size = length + 1;  // +1 for null terminator
    auto buffer = std::make_unique<UChar[]>(buffer_size);
    status = U_ZERO_ERROR;
    length = icu_.ucal_getTimeZoneDisplayName(ptr_, type, nullptr, buffer.get(),
                                              buffer_size, &status);
    if (U_FAILURE(status) || length <= 0) {
      return std::string();
    }
    return Utf16ToUtf8(buffer.get(), length);
  }

  UCalendar* ptr_;
  UCalendar** cache_ptr_;
  const IcuFunctions& icu_;
};

// This class provides the same way to obtain `ThreadLocalUCalendarOperation`
// with optional object recycling.
//
// When accessing this object from a different thread than the one that created
// it, the "Happens-Before" relationship must be ensured in a higher layer (e.g.
// with `std::atomic` or `std::mutex`). The following implementation assumes
// that all the memory writes before instantiating this object are visible to
// all threads that access it.
class UCalendarOperationFactory final {
 public:
  UCalendarOperationFactory() = delete;
  UCalendarOperationFactory(const UCalendarOperationFactory&) = delete;
  UCalendarOperationFactory(UCalendarOperationFactory&&) = delete;

  UCalendarOperationFactory(IcuFunctions::ScopedUCalendar prototype,
                            const IcuFunctions& icu)
      : prototype_(std::move(prototype)),
        thread_local_cache_(nullptr),
        icu_(icu),
        cacheable_thread_id_(::GetCurrentThreadId()) {}

  ~UCalendarOperationFactory() {
    if (thread_local_cache_ != nullptr) {
      icu_.ucal_close(thread_local_cache_);
      thread_local_cache_ = nullptr;
    }
  }

  // For performance reasons, the initial state of
  // `ThreadLocalUCalendarOperation` can be carried over from the previous
  // operation. The user is responsible for resetting all the state of the
  // UCalendar that is relevant to their read operations.
  ThreadLocalUCalendarOperation ReuseOrNew() const {
    if (cacheable_thread_id_ == ::GetCurrentThreadId()) {
      // Try to reuse the thread-local cache.
      UCalendar* cal = thread_local_cache_;
      thread_local_cache_ = nullptr;
      if (cal == nullptr) {
        UErrorCode status = U_ZERO_ERROR;
        cal = icu_.ucal_clone(prototype_.get(), &status);
        if (U_FAILURE(status) || cal == nullptr) {
          return ThreadLocalUCalendarOperation(nullptr, nullptr, icu_);
        }
      }
      return ThreadLocalUCalendarOperation(cal, &thread_local_cache_, icu_);
    }
    // The key assumption here is that `prototype_` can be safely cloned with
    // `ucal_clone` even when accessed from a thread where `prototype_` was
    // created. Here we rely on the transitivity in "Happens-Before"
    // relationships by not modifying `prototype_` after its creation.
    // https://unicode-org.github.io/icu/userguide/icu/design.html#thread-safe-const-apis
    UErrorCode status = U_ZERO_ERROR;
    UCalendar* clone = icu_.ucal_clone(prototype_.get(), &status);
    if (U_FAILURE(status) || clone == nullptr) {
      return ThreadLocalUCalendarOperation(nullptr, nullptr, icu_);
    }
    return ThreadLocalUCalendarOperation(clone, nullptr, icu_);
  }

 private:
  const IcuFunctions::ScopedUCalendar prototype_;
  mutable UCalendar* thread_local_cache_;
  const IcuFunctions icu_;
  const DWORD cacheable_thread_id_;
};

class TimeZoneIcuWin final : public TimeZoneIf {
 public:
  TimeZoneIcuWin(IcuFunctions icu, IcuFunctions::ScopedUCalendar prototype)
      : icu_(icu), calendar_ops_(std::move(prototype), icu) {}
  TimeZoneIcuWin(const TimeZoneIcuWin&) = delete;
  TimeZoneIcuWin(TimeZoneIcuWin&&) = delete;
  TimeZoneIcuWin& operator=(const TimeZoneIcuWin&) = delete;

  static std::unique_ptr<TimeZoneIf> Create(const std::string& name) {
    const auto icu = IcuFunctions::Get();
    if (!icu.available) {
      return nullptr;
    }
    auto cal = OpenCalendar(icu, name);
    if (!cal) {
      return nullptr;
    }
    return std::make_unique<TimeZoneIcuWin>(icu, std::move(cal));
  }

  // TimeZoneIf implementations.
  time_zone::absolute_lookup BreakTime(
      const time_point<seconds>& tp) const override {
    time_zone::absolute_lookup result;
    icu_absolute_lookup lookup;
    if (!calendar_ops_.ReuseOrNew().BreakTime(ToUDate(tp), &lookup)) {
      return result;
    }

    result.cs = lookup.cs;
    result.is_dst = lookup.is_dst;
    result.offset = lookup.offset;
    result.abbr = string_holder_.Intern(lookup.abbr);
    return result;
  }

  time_zone::civil_lookup MakeTime(const civil_second& cs) const override {
    icu_civil_lookup lookup;
    time_zone::civil_lookup result;
    if (calendar_ops_.ReuseOrNew().MakeTime(cs, &lookup)) {
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
    if (!calendar_ops_.ReuseOrNew().NextTransition(
            tp.time_since_epoch().count() * 1000.0, &transition)) {
      return false;
    }
    trans->from = transition.from;
    trans->to = transition.to;
    return true;
  }

  bool PrevTransition(const time_point<seconds>& tp,
                      time_zone::civil_transition* trans) const override {
    icu_civil_transition transition;
    if (!calendar_ops_.ReuseOrNew().PrevTransition(
            tp.time_since_epoch().count() * 1000.0, &transition)) {
      return false;
    }
    trans->from = transition.from;
    trans->to = transition.to;
    return true;
  }

  std::string Version() const override {
    UErrorCode status = U_ZERO_ERROR;
    const char* version = icu_.ucal_getTZDataVersion(&status);
    if (U_FAILURE(status) || version == nullptr) {
      return std::string();
    }
    return version;
  }

  std::string Description() const override { return std::string(); }

 private:
  static IcuFunctions::ScopedUCalendar OpenCalendar(const IcuFunctions& icu,
                                                    const std::string& name) {
    auto zone_id = Utf8ToUtf16(name);
    if (zone_id.empty()) {
      return IcuFunctions::ScopedUCalendar(nullptr, nullptr);
    }
    if (zone_id.size() > std::numeric_limits<int>::max()) {
      return IcuFunctions::ScopedUCalendar(nullptr, nullptr);
    }
    const int zone_id_size = static_cast<int>(zone_id.size());
    UErrorCode status = U_ZERO_ERROR;

    int length = 0;
    {
      const int buffer_size = 32;
      UChar buffer[buffer_size];
      UBool is_system = false;
      length =
          icu.ucal_getCanonicalTimeZoneID(zone_id.c_str(), zone_id_size, buffer,
                                          buffer_size, &is_system, &status);
      if (U_SUCCESS(status) && 0 < length && length <= buffer_size) {
        status = U_ZERO_ERROR;
        UCalendar* cal =
            icu.ucal_open(buffer, length, nullptr, UCAL_GREGORIAN, &status);
        if (U_FAILURE(status)) {
          return IcuFunctions::ScopedUCalendar(nullptr, nullptr);
        }
        return IcuFunctions::ScopedUCalendar(cal, icu.ucal_close);
      }
      if (status != U_BUFFER_OVERFLOW_ERROR || length <= 0) {
        return IcuFunctions::ScopedUCalendar(nullptr, nullptr);
      }
    }

    const int buffer_size = length + 1;  // +1 for null terminator
    auto buffer = std::make_unique<UChar[]>(buffer_size);
    UBool is_system = false;
    status = U_ZERO_ERROR;
    length = icu.ucal_getCanonicalTimeZoneID(zone_id.c_str(), zone_id_size,
                                             buffer.get(), buffer_size,
                                             &is_system, &status);
    if (U_FAILURE(status) || length <= 0 || buffer_size < length) {
      return IcuFunctions::ScopedUCalendar(nullptr, nullptr);
    }
    UCalendar* cal =
        icu.ucal_open(buffer.get(), length, nullptr, UCAL_GREGORIAN, &status);
    if (U_FAILURE(status)) {
      return IcuFunctions::ScopedUCalendar(nullptr, nullptr);
    }
    return IcuFunctions::ScopedUCalendar(cal, icu.ucal_close);
  }

  const IcuFunctions icu_;
  const UCalendarOperationFactory calendar_ops_;
  mutable ShortStringPool string_holder_;
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
    auto buffer = std::make_unique<UChar[]>(buffer_size);
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
  auto buffer = std::make_unique<UChar[]>(buffer_size);
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

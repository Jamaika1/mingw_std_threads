// std::mutex implementation -*- C++ -*-

// Copyright (C) 2003-2022 Free Software Foundation, Inc.
//
// This file is part of the GNU ISO C++ Library.  This library is free
// software; you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the
// Free Software Foundation; either version 3, or (at your option)
// any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// Under Section 7 of GPL version 3, you are granted additional
// permissions described in the GCC Runtime Library Exception, version
// 3.1, as published by the Free Software Foundation.

// You should have received a copy of the GNU General Public License and
// a copy of the GCC Runtime Library Exception along with this program;
// see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
// <http://www.gnu.org/licenses/>.

/** @file bits/std_mutex.h
 *  This is an internal header file, included by other library headers.
 *  Do not attempt to use it directly. @headername{mutex}
 */

#ifndef _GLIBCXX_MUTEX_H
#define _GLIBCXX_MUTEX_H 1

#pragma GCC system_header

#if __cplusplus < 201103L
# include <bits/c++0x_warning.h>
#else

#include <system_error>
#include <bits/functexcept.h>
#include <bits/gthr.h>

#ifndef _GLIBCXX_HAS_GTHREADS
# include <bits/mingw.invoke.h>
#endif

namespace std _GLIBCXX_VISIBILITY(default)
{
_GLIBCXX_BEGIN_NAMESPACE_VERSION

  /**
   * @addtogroup mutexes
   * @{
   */

#ifdef MINGWSTD
#include <atomic>
#if STDMUTEX_RECURSION_CHECKS
#include <cstdio>
#endif

#include <sdkddkver.h>  //  Detect Windows version.

#if (defined(__MINGW32__) && !defined(__MINGW64_VERSION_MAJOR))
#pragma message "The Windows API that MinGW-w32 provides is not fully compatible\
 with Microsoft's API. We'll try to work around this, but we can make no\
 guarantees. This problem does not exist in MinGW-w64."
#include <windows.h>    //  No further granularity can be expected.
#else
#if STDMUTEX_RECURSION_CHECKS
#include <processthreadsapi.h>  //  For GetCurrentThreadId
#endif
#include <synchapi.h> //  For InitializeCriticalSection, etc.
#include <errhandlingapi.h> //  For GetLastError
#include <handleapi.h>
#endif

//    The _NonRecursive class has mechanisms that do not play nice with direct
//  manipulation of the native handle. This forward declaration is part of
//  a friend class declaration.
#if STDMUTEX_RECURSION_CHECKS
namespace vista { class condition_variable; }
#endif

class recursive_mutex
{
    CRITICAL_SECTION mHandle;
public:
    typedef LPCRITICAL_SECTION native_handle_type;
    native_handle_type native_handle() {return &mHandle;}
    recursive_mutex() noexcept : mHandle()
    {
        InitializeCriticalSection(&mHandle);
    }
    recursive_mutex (const recursive_mutex&) = delete;
    recursive_mutex& operator=(const recursive_mutex&) = delete;
    ~recursive_mutex() noexcept
    {
        DeleteCriticalSection(&mHandle);
    }
    void lock()
    {
        EnterCriticalSection(&mHandle);
    }
    void unlock()
    {
        LeaveCriticalSection(&mHandle);
    }
    bool try_lock()
    {
        return (TryEnterCriticalSection(&mHandle)!=0);
    }
};

#if STDMUTEX_RECURSION_CHECKS
struct _OwnerThread
{
//    If this is to be read before locking, then the owner-thread variable must
//  be atomic to prevent a torn read from spuriously causing errors.
    std::atomic<DWORD> mOwnerThread;
    constexpr _OwnerThread () noexcept : mOwnerThread(0) {}
    static void on_deadlock (void)
    {
        using namespace std;
        fprintf(stderr, "FATAL: Recursive locking of non-recursive mutex\
 detected. Throwing system exception\n");
        fflush(stderr);
        throw system_error(make_error_code(errc::resource_deadlock_would_occur));
    }
    DWORD checkOwnerBeforeLock() const
    {
        DWORD self = GetCurrentThreadId();
        if (mOwnerThread.load(std::memory_order_relaxed) == self)
            on_deadlock();
        return self;
    }
    void setOwnerAfterLock(DWORD id)
    {
        mOwnerThread.store(id, std::memory_order_relaxed);
    }
    void checkSetOwnerBeforeUnlock()
    {
        DWORD self = GetCurrentThreadId();
        if (mOwnerThread.load(std::memory_order_relaxed) != self)
            on_deadlock();
        mOwnerThread.store(0, std::memory_order_relaxed);
    }
};
#endif

// Define SRWLOCK_INIT.
#if !defined(SRWLOCK_INIT)
#pragma message "SRWLOCK_INIT macro is not defined. Defining automatically."
#define SRWLOCK_INIT {0}
#endif

//    Though the Slim Reader-Writer (SRW) locks used here are not complete until
//  Windows 7, implementing partial functionality in Vista will simplify the
//  interaction with condition variables.
#if defined(_WIN32) && (WINVER >= _WIN32_WINNT_VISTA)
namespace windows7
{
class mutex
{
    SRWLOCK mHandle;
//  Track locking thread for error checking.
public:
#if STDMUTEX_RECURSION_CHECKS
    friend class vista::condition_variable;
    _OwnerThread mOwnerThread {};
#endif
    typedef PSRWLOCK native_handle_type;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
    constexpr mutex () noexcept : mHandle(SRWLOCK_INIT) { }
#pragma GCC diagnostic pop
    mutex (const mutex&) = delete;
    mutex & operator= (const mutex&) = delete;
    void lock (void)
    {
//  Note: Undefined behavior if called recursively.
#if STDMUTEX_RECURSION_CHECKS
        DWORD self = mOwnerThread.checkOwnerBeforeLock();
#endif
        AcquireSRWLockExclusive(&mHandle);
#if STDMUTEX_RECURSION_CHECKS
        mOwnerThread.setOwnerAfterLock(self);
#endif
    }
    void unlock (void)
    {
#if STDMUTEX_RECURSION_CHECKS
        mOwnerThread.checkSetOwnerBeforeUnlock();
#endif
        ReleaseSRWLockExclusive(&mHandle);
    }
//  TryAcquireSRW functions are a Windows 7 feature.
#if (WINVER >= _WIN32_WINNT_WIN7)
    bool try_lock (void)
    {
#if STDMUTEX_RECURSION_CHECKS
        DWORD self = mOwnerThread.checkOwnerBeforeLock();
#endif
        BOOL ret = TryAcquireSRWLockExclusive(&mHandle);
#if STDMUTEX_RECURSION_CHECKS
        if (ret)
            mOwnerThread.setOwnerAfterLock(self);
#endif
        return ret;
    }
#endif
    native_handle_type native_handle (void)
    {
        return &mHandle;
    }
};
} //  Namespace windows7
#endif  //  Compiling for Vista
namespace xp
{
class mutex
{
    CRITICAL_SECTION mHandle;
    std::atomic_uchar mState;
//  Track locking thread for error checking.
public:
#if STDMUTEX_RECURSION_CHECKS
    friend class vista::condition_variable;
    _OwnerThread mOwnerThread {};
#endif
    typedef PCRITICAL_SECTION native_handle_type;
    constexpr mutex () noexcept : mHandle(), mState(2) { }
    mutex (const mutex&) = delete;
    mutex & operator= (const mutex&) = delete;
    ~mutex() noexcept
    {
//    Undefined behavior if the mutex is held (locked) by any thread.
//    Undefined behavior if a thread terminates while holding ownership of the
//  mutex.
        DeleteCriticalSection(&mHandle);
    }
    void lock (void)
    {
        unsigned char state = mState.load(std::memory_order_acquire);
        while (state) {
            if ((state == 2) && mState.compare_exchange_weak(state, 1, std::memory_order_acquire))
            {
                InitializeCriticalSection(&mHandle);
                mState.store(0, std::memory_order_release);
                break;
            }
            if (state == 1)
            {
                Sleep(0);
                state = mState.load(std::memory_order_acquire);
            }
        }
#if STDMUTEX_RECURSION_CHECKS
        DWORD self = mOwnerThread.checkOwnerBeforeLock();
#endif
        EnterCriticalSection(&mHandle);
#if STDMUTEX_RECURSION_CHECKS
        mOwnerThread.setOwnerAfterLock(self);
#endif
    }
    void unlock (void)
    {
#if STDMUTEX_RECURSION_CHECKS
        mOwnerThread.checkSetOwnerBeforeUnlock();
#endif
        LeaveCriticalSection(&mHandle);
    }
    bool try_lock (void)
    {
        unsigned char state = mState.load(std::memory_order_acquire);
        if ((state == 2) && mState.compare_exchange_strong(state, 1, std::memory_order_acquire))
        {
            InitializeCriticalSection(&mHandle);
            mState.store(0, std::memory_order_release);
        }
        if (state == 1)
            return false;
#if STDMUTEX_RECURSION_CHECKS
        DWORD self = mOwnerThread.checkOwnerBeforeLock();
#endif
        BOOL ret = TryEnterCriticalSection(&mHandle);
#if STDMUTEX_RECURSION_CHECKS
        if (ret)
            mOwnerThread.setOwnerAfterLock(self);
#endif
        return ret;
    }
    native_handle_type native_handle (void)
    {
        return &mHandle;
    }
};
} //  Namespace xp

#if (WINVER >= _WIN32_WINNT_WIN7)
using windows7::mutex;
#else
using xp::mutex;
#endif

class recursive_timed_mutex
{
    static constexpr DWORD kWaitAbandoned = 0x00000080l;
    static constexpr DWORD kWaitObject0 = 0x00000000l;
    static constexpr DWORD kInfinite = 0xffffffffl;
    inline bool try_lock_internal (DWORD ms) noexcept
    {
        DWORD ret = WaitForSingleObject(mHandle, ms);
#if STDMUTEX_RECURSION_CHECKS
        if (ret == kWaitAbandoned)
        {
            using namespace std;
            fprintf(stderr, "FATAL: Thread terminated while holding a mutex.");
            terminate();
        }
#endif
        return (ret == kWaitObject0) || (ret == kWaitAbandoned);
    }
protected:
    HANDLE mHandle;
//    Track locking thread for error checking of non-recursive timed_mutex. For
//  standard compliance, this must be defined in same class and at the same
//  access-control level as every other variable in the timed_mutex.
#if STDMUTEX_RECURSION_CHECKS
    friend class vista::condition_variable;
    _OwnerThread mOwnerThread {};
#endif
public:
    typedef HANDLE native_handle_type;
    native_handle_type native_handle() const {return mHandle;}
    recursive_timed_mutex(const recursive_timed_mutex&) = delete;
    recursive_timed_mutex& operator=(const recursive_timed_mutex&) = delete;
    recursive_timed_mutex(): mHandle(CreateMutex(NULL, FALSE, NULL)) {}
    ~recursive_timed_mutex()
    {
        CloseHandle(mHandle);
    }
    void lock()
    {
        DWORD ret = WaitForSingleObject(mHandle, kInfinite);
//    If (ret == WAIT_ABANDONED), then the thread that held ownership was
//  terminated. Behavior is undefined, but Windows will pass ownership to this
//  thread.
#if STDMUTEX_RECURSION_CHECKS
        if (ret == kWaitAbandoned)
        {
            using namespace std;
            fprintf(stderr, "FATAL: Thread terminated while holding a mutex.");
            terminate();
        }
#endif
        if ((ret != kWaitObject0) && (ret != kWaitAbandoned))
        {
            throw std::system_error(GetLastError(), std::system_category());
        }
    }
    void unlock()
    {
        if (!ReleaseMutex(mHandle))
            throw std::system_error(GetLastError(), std::system_category());
    }
    bool try_lock()
    {
        return try_lock_internal(0);
    }
    template <class Rep, class Period>
    bool try_lock_for(const std::chrono::duration<Rep,Period>& dur)
    {
        using namespace std::chrono;
        auto timeout = duration_cast<milliseconds>(dur).count();
        while (timeout > 0)
        {
          constexpr auto kMaxStep = static_cast<decltype(timeout)>(kInfinite-1);
          auto step = (timeout < kMaxStep) ? timeout : kMaxStep;
          if (try_lock_internal(static_cast<DWORD>(step)))
            return true;
          timeout -= step;
        }
        return false;
    }
    template <class Clock, class Duration>
    bool try_lock_until(const std::chrono::time_point<Clock,Duration>& timeout_time)
    {
        return try_lock_for(timeout_time - Clock::now());
    }
};

//  Override if, and only if, it is necessary for error-checking.
#if STDMUTEX_RECURSION_CHECKS
class timed_mutex: recursive_timed_mutex
{
public:
    timed_mutex() = default;
    timed_mutex(const timed_mutex&) = delete;
    timed_mutex& operator=(const timed_mutex&) = delete;
    void lock()
    {
        DWORD self = mOwnerThread.checkOwnerBeforeLock();
        recursive_timed_mutex::lock();
        mOwnerThread.setOwnerAfterLock(self);
    }
    void unlock()
    {
        mOwnerThread.checkSetOwnerBeforeUnlock();
        recursive_timed_mutex::unlock();
    }
    template <class Rep, class Period>
    bool try_lock_for(const std::chrono::duration<Rep,Period>& dur)
    {
        DWORD self = mOwnerThread.checkOwnerBeforeLock();
        bool ret = recursive_timed_mutex::try_lock_for(dur);
        if (ret)
            mOwnerThread.setOwnerAfterLock(self);
        return ret;
    }
    template <class Clock, class Duration>
    bool try_lock_until(const std::chrono::time_point<Clock,Duration>& timeout_time)
    {
        return try_lock_for(timeout_time - Clock::now());
    }
    bool try_lock ()
    {
        return try_lock_for(std::chrono::milliseconds(0));
    }
};
#else
typedef recursive_timed_mutex timed_mutex;
#endif
#endif // MINGWSTD

#ifdef _GLIBCXX_HAS_GTHREADS
  /// @cond undocumented

  // Common base class for std::mutex and std::timed_mutex
  class __mutex_base
  {
  protected:
    typedef __gthread_mutex_t			__native_type;

#ifdef __GTHREAD_MUTEX_INIT
    __native_type  _M_mutex = __GTHREAD_MUTEX_INIT;

    constexpr __mutex_base() noexcept = default;
#else
    __native_type  _M_mutex;

    __mutex_base() noexcept
    {
      // XXX EAGAIN, ENOMEM, EPERM, EBUSY(may), EINVAL(may)
      __GTHREAD_MUTEX_INIT_FUNCTION(&_M_mutex);
    }

    ~__mutex_base() noexcept { __gthread_mutex_destroy(&_M_mutex); }
#endif

    __mutex_base(const __mutex_base&) = delete;
    __mutex_base& operator=(const __mutex_base&) = delete;
  };
  /// @endcond

  /** The standard mutex type.
   *
   * A simple, non-recursive, non-timed mutex.
   *
   * Do not call `lock()` and `unlock()` directly, use a scoped lock type
   * such as `std::unique_lock`, `std::lock_guard`, or (since C++17)
   * `std::scoped_lock`.
   *
   * @headerfile mutex
   * @since C++11
   */
  class mutex : private __mutex_base
  {
  public:
    typedef __native_type* 			native_handle_type;

#ifdef __GTHREAD_MUTEX_INIT
    constexpr
#endif
    mutex() noexcept = default;
    ~mutex() = default;

    mutex(const mutex&) = delete;
    mutex& operator=(const mutex&) = delete;

    void
    lock()
    {
      int __e = __gthread_mutex_lock(&_M_mutex);

      // EINVAL, EAGAIN, EBUSY, EINVAL, EDEADLK(may)
      if (__e)
	__throw_system_error(__e);
    }

    _GLIBCXX_NODISCARD
    bool
    try_lock() noexcept
    {
      // XXX EINVAL, EAGAIN, EBUSY
      return !__gthread_mutex_trylock(&_M_mutex);
    }

    void
    unlock()
    {
      // XXX EINVAL, EAGAIN, EPERM
      __gthread_mutex_unlock(&_M_mutex);
    }

    native_handle_type
    native_handle() noexcept
    { return &_M_mutex; }
  };

  /// @cond undocumented

  // Implementation details for std::condition_variable
  class __condvar
  {
    using timespec = __gthread_time_t;

  public:
    __condvar() noexcept
    {
#ifndef __GTHREAD_COND_INIT
      __GTHREAD_COND_INIT_FUNCTION(&_M_cond);
#endif
    }

    ~__condvar()
    {
      int __e __attribute__((__unused__)) = __gthread_cond_destroy(&_M_cond);
      __glibcxx_assert(__e != EBUSY); // threads are still blocked
    }

    __condvar(const __condvar&) = delete;
    __condvar& operator=(const __condvar&) = delete;

    __gthread_cond_t* native_handle() noexcept { return &_M_cond; }

    // Expects: Calling thread has locked __m.
    void
    wait(mutex& __m)
    {
      int __e __attribute__((__unused__))
	= __gthread_cond_wait(&_M_cond, __m.native_handle());
      __glibcxx_assert(__e == 0);
    }

    void
    wait_until(mutex& __m, timespec& __abs_time)
    {
      __gthread_cond_timedwait(&_M_cond, __m.native_handle(), &__abs_time);
    }

#ifdef _GLIBCXX_USE_PTHREAD_COND_CLOCKWAIT
    void
    wait_until(mutex& __m, clockid_t __clock, timespec& __abs_time)
    {
      pthread_cond_clockwait(&_M_cond, __m.native_handle(), __clock,
			     &__abs_time);
    }
#endif

    void
    notify_one() noexcept
    {
      int __e __attribute__((__unused__)) = __gthread_cond_signal(&_M_cond);
      __glibcxx_assert(__e == 0);
    }

    void
    notify_all() noexcept
    {
      int __e __attribute__((__unused__)) = __gthread_cond_broadcast(&_M_cond);
      __glibcxx_assert(__e == 0);
    }

  protected:
#ifdef __GTHREAD_COND_INIT
    __gthread_cond_t _M_cond = __GTHREAD_COND_INIT;
#else
    __gthread_cond_t _M_cond;
#endif
  };
  /// @endcond

#endif // _GLIBCXX_HAS_GTHREADS

  /// Do not acquire ownership of the mutex.
  struct defer_lock_t { explicit defer_lock_t() = default; };

  /// Try to acquire ownership of the mutex without blocking.
  struct try_to_lock_t { explicit try_to_lock_t() = default; };

  /// Assume the calling thread has already obtained mutex ownership
  /// and manage it.
  struct adopt_lock_t { explicit adopt_lock_t() = default; };

  /// Tag used to prevent a scoped lock from acquiring ownership of a mutex.
  _GLIBCXX17_INLINE constexpr defer_lock_t	defer_lock { };

  /// Tag used to prevent a scoped lock from blocking if a mutex is locked.
  _GLIBCXX17_INLINE constexpr try_to_lock_t	try_to_lock { };

  /// Tag used to make a scoped lock take ownership of a locked mutex.
  _GLIBCXX17_INLINE constexpr adopt_lock_t	adopt_lock { };

  /** @brief A simple scoped lock type.
   *
   * A lock_guard controls mutex ownership within a scope, releasing
   * ownership in the destructor.
   *
   * @headerfile mutex
   * @since C++11
   */
  template<typename _Mutex>
    class lock_guard
    {
    public:
      typedef _Mutex mutex_type;

      explicit lock_guard(mutex_type& __m) : _M_device(__m)
      { _M_device.lock(); }

      lock_guard(mutex_type& __m, adopt_lock_t) noexcept : _M_device(__m)
      { } // calling thread owns mutex

      ~lock_guard()
      { _M_device.unlock(); }

      lock_guard(const lock_guard&) = delete;
      lock_guard& operator=(const lock_guard&) = delete;

    private:
      mutex_type&  _M_device;
    };

  /// @} group mutexes
_GLIBCXX_END_NAMESPACE_VERSION
} // namespace
#endif // C++11
#endif // _GLIBCXX_MUTEX_H

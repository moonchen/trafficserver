#pragma once

#include <functional>

class ScopeGuard
{
public:
  ScopeGuard(const std::function<void()> &method) : _cleanup_method(method) {}
  ScopeGuard(ScopeGuard &other)            = delete;
  ScopeGuard &operator=(ScopeGuard &other) = delete;

  void
  reset()
  {
    _cleanup_method = [] {};
  }

  ~ScopeGuard() { _cleanup_method(); }

private:
  std::function<void()> _cleanup_method;
};

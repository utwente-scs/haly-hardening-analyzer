import threading

"""
Decorator similar to functools.cache, but it caches the result per thread instead of sharing it across all threads.
"""


def per_thread_singleton(cls):
    class SingletonWrapper:
        _instances = threading.local()

        def __call__(self, *args, **kwargs):
            if not hasattr(self._instances, "instance"):
                self._instances.instance = cls(*args, **kwargs)
            return self._instances.instance

        @classmethod
        def cache_clear(cls):
            if hasattr(cls._instances, "instance"):
                delattr(cls._instances, "instance")

    return SingletonWrapper()

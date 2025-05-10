import unittest
from src.api_scoring.store import Store

class TestStoreIntegration(unittest.TestCase):
    def setUp(self):
        self.store = Store(host='localhost', port=6379, db=0)

    def test_set_and_get(self):
        key = "test_key"
        value = "test_value"
        self.store.set(key, value)
        result = self.store.get(key)
        self.assertEqual(result.decode('utf-8'), value)

    def test_cache_get(self):
        key = "cache_key"
        value = "cached_value"
        self.store.set(key, value)
        result = self.store.cache_get(key)
        self.assertEqual(result.decode('utf-8'), value)
import logging
import time
import socket
import redis

logger = logging.getLogger(__name__)

class Store:
    def __init__(self, host='localhost', port=6379, db=0, retries=3, timeout=1):
        self.host = 'localhost'
        self.port = 6379
        self.db = db
        self.retries = retries
        self.timeout = timeout
        self.client = None
        self.connect()

    def connect(self):
        for attempt in range(self.retries):
            try:
                self.client = redis.StrictRedis(
                    host=self.host,
                    port=self.port,
                    db=self.db,
                    socket_timeout=self.timeout
                )
                self.client.ping()  # Проверка соединения
                logger.info("Connected to Redis")
                return
            except (redis.ConnectionError, socket.timeout) as e:
                logger.error(f"Connection attempt {attempt + 1} failed: {e}")
                time.sleep(1)
        raise ConnectionError("Could not connect to Redis after multiple attempts")

    def get(self, key):
        try:
            return self.client.get(key)
        except (redis.ConnectionError, socket.timeout) as e:
            logger.warning(f"Store get failed: {e}")
            return None

    def set(self, key, value, expire=None):
        try:
            return self.client.set(key, value, ex=expire)
        except (redis.ConnectionError, socket.timeout) as e:
            logger.warning(f"Store set failed: {e}")
            return False

    def cache_get(self, key):
        return self.get(key)  # В данном случае аналогично get, но можно доработать логику
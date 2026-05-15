import asyncio
import json
import logging
import os
from typing import List, Optional

import redis.asyncio as redis

logger = logging.getLogger(__name__)


class RedisManager:
    def __init__(self, host: str, port: int, db: int, password: Optional[str] = None):
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self._client: Optional[redis.Redis] = None
        self._signing_key = os.getenv("REDIS_SIGNING_KEY")

    async def connect(self):
        if not self._client:
            self._client = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                decode_responses=True,
            )
            await self._client.ping()
        return self._client

    async def get_dial(self) -> int:
        client = await self.connect()
        val = await client.get("config:dial")
        if val is None:
            return 0
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0

    async def set_dial(self, value: int):
        client = await self.connect()
        # Authoritative value is in config:dial
        await client.set("config:dial", str(value))

        # Notify proxy instances via pub/sub
        msg = {"type": "dial_change", "value": str(value)}

        if self._signing_key:
            import hashlib
            import hmac

            data = f"dial_change:{value}".encode("utf-8")
            h = hmac.new(self._signing_key.encode("utf-8"), data, hashlib.sha256)
            msg["signature"] = h.hexdigest()

        await client.publish("ja4proxy:invalidate", json.dumps(msg))

    async def get_list(self, list_name: str) -> List[str]:
        client = await self.connect()
        key = f"ja4:{list_name}"
        members = await client.smembers(key)
        return sorted(list(members))

    async def add_to_list(self, list_name: str, value: str):
        client = await self.connect()
        key = f"ja4:{list_name}"
        await client.sadd(key, value)

        # If blacklisting, notify proxy instances immediately
        if list_name == "blacklist":
            msg = {"type": "ja4_blacklist_add", "value": value}
            if self._signing_key:
                import hashlib
                import hmac

                data = f"ja4_blacklist_add:{value}".encode("utf-8")
                h = hmac.new(self._signing_key.encode("utf-8"), data, hashlib.sha256)
                msg["signature"] = h.hexdigest()

            await client.publish("ja4proxy:invalidate", json.dumps(msg))

    async def remove_from_list(self, list_name: str, value: str):
        client = await self.connect()
        key = f"ja4:{list_name}"
        await client.srem(key, value)

        # If removing from whitelist, notify proxy instances to invalidate cache
        if list_name == "whitelist":
            msg = {"type": "whitelist_remove", "value": value}
            await client.publish("ja4proxy:invalidate", json.dumps(msg))

    async def get_events(self):
        """Subscribe to ja4proxy:events channel for live feed."""
        client = await self.connect()
        async with client.pubsub() as ps:
            await ps.subscribe("ja4proxy:events")
            async for message in ps.listen():
                if message["type"] == "message":
                    yield message["data"]

    async def close(self):
        if self._client:
            await self._client.close()
            self._client = None

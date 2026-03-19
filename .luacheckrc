-- luacheck configuration for JA4proxy
-- https://luacheck.readthedocs.io/
--
-- KEYS, ARGV, and redis are injected by the Redis runtime when scripts are
-- executed via EVAL / EVALSHA. They are not standard Lua globals but are
-- always present in the Redis scripting environment.

globals = {
    "redis",   -- Redis client object (redis.call, redis.pcall, redis.log)
    "KEYS",    -- Table of key arguments passed to EVAL
    "ARGV",    -- Table of value arguments passed to EVAL
    "cjson",   -- JSON encoder/decoder (built into Redis)
    "cmsgpack",-- MessagePack (built into Redis)
    "struct",  -- Struct pack/unpack (built into Redis)
}

#!/usr/bin/env python3
"""
Set the proxy dial value via pubsub.
Usage: python set_dial.py <dial_value> [redis_host] [redis_port]
"""

import json
import sys

import redis


def set_dial_via_pubsub(dial_value, redis_host='localhost', redis_port=6379):
    """Publish a dial change message to the pubsub channel."""
    try:
        # Connect to Redis
        r = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
        
        # Publish dial change message
        message = {
            "type": "dial_change",
            "value": str(dial_value)
        }
        
        published = r.publish("ja4proxy:invalidate", json.dumps(message))
        
        print("✅ Dial change message published successfully!")
        print("   Channel: ja4proxy:invalidate")
        print(f"   Message: {message}")
        print(f"   Subscribers reached: {published}")
        
        if published == 0:
            print("⚠️  Warning: No subscribers received the message")
            print("   Make sure the proxy is running and connected to Redis")
        
        return True
        
    except redis.ConnectionError as e:
        print(f"❌ Failed to connect to Redis: {e}")
        return False
    except Exception as e:
        print(f"❌ Error publishing message: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dial_value> [redis_host] [redis_port]")
        print(f"Example: {sys.argv[0]} 50")
        sys.exit(1)
    
    dial_value = int(sys.argv[1])
    redis_host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
    redis_port = int(sys.argv[3]) if len(sys.argv) > 3 else 6379
    
    if dial_value < 0 or dial_value > 100:
        print("❌ Dial value must be between 0 and 100")
        sys.exit(1)
    
    print(f"Setting dial to {dial_value} via pubsub...")
    success = set_dial_via_pubsub(dial_value, redis_host, redis_port)
    
    if success:
        print("\n✅ Dial change initiated!")
        print(f"   The proxy should now use dial={dial_value} for blocking decisions")
        print(f"   Check proxy logs for: 'pubsub | event=dial_change | dial={dial_value}'")
    else:
        print("\n❌ Failed to set dial")
        sys.exit(1)

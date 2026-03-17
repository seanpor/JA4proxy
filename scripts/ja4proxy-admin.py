#!/usr/bin/env python3
"""
JA4Proxy Admin CLI - Phase 16

Command-line interface for administrative operations on JA4Proxy.
Provides safe, documented alternatives to direct Redis manipulation.
"""

import click
import redis
import sys
from typing import Optional


class AdminCLI:
    """JA4Proxy administrative command-line interface."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        """Initialize admin CLI with Redis connection."""
        self.redis_url = redis_url
        self.redis = None
        
    def connect(self):
        """Establish Redis connection."""
        try:
            self.redis = redis.Redis.from_url(self.redis_url)
            # Test connection
            self.redis.ping()
            return True
        except Exception as e:
            print(f"❌ Error connecting to Redis: {e}", file=sys.stderr)
            return False
    
    # IP Management
    def ban_ip(self, ip: str, ttl: int = 3600, confirm: bool = False):
        """Ban an IP address."""
        if not confirm:
            print("⚠️  --confirm required to ban IP", file=sys.stderr)
            return False
        
        try:
            key = f"ban:{ip}"
            self.redis.setex(key, ttl, "banned")
            print(f"✅ Banned IP {ip} for {ttl} seconds")
            return True
        except Exception as e:
            print(f"❌ Error banning IP: {e}", file=sys.stderr)
            return False
    
    def unban_ip(self, ip: str, confirm: bool = False):
        """Unban an IP address."""
        if not confirm:
            print("⚠️  --confirm required to unban IP", file=sys.stderr)
            return False
        
        try:
            key = f"ban:{ip}"
            result = self.redis.delete(key)
            if result:
                print(f"✅ Unbanned IP {ip}")
            else:
                print(f"ℹ️  IP {ip} was not banned")
            return True
        except Exception as e:
            print(f"❌ Error unbanning IP: {e}", file=sys.stderr)
            return False
    
    # JA4 Management
    def whitelist_ja4(self, ja4: str, confirm: bool = False):
        """Whitelist a JA4 fingerprint."""
        if not confirm:
            print("⚠️  --confirm required to whitelist JA4", file=sys.stderr)
            return False
        
        try:
            self.redis.sadd("ja4:whitelist", ja4)
            print(f"✅ Whitelisted JA4: {ja4}")
            return True
        except Exception as e:
            print(f"❌ Error whitelisting JA4: {e}", file=sys.stderr)
            return False
    
    def blacklist_ja4(self, ja4: str, confirm: bool = False):
        """Blacklist a JA4 fingerprint."""
        if not confirm:
            print("⚠️  --confirm required to blacklist JA4", file=sys.stderr)
            return False
        
        try:
            self.redis.sadd("ja4:blacklist", ja4)
            print(f"✅ Blacklisted JA4: {ja4}")
            return True
        except Exception as e:
            print(f"❌ Error blacklisting JA4: {e}", file=sys.stderr)
            return False
    
    # Dial Management
    def get_dial(self):
        """Get current dial value."""
        try:
            dial = self.redis.get("ja4proxy:dial")
            if dial:
                print(f"Current dial: {dial.decode()}")
                return dial.decode()
            else:
                print("No dial value set (default: 100)")
                return "100"
        except Exception as e:
            print(f"❌ Error getting dial: {e}", file=sys.stderr)
            return None
    
    def set_dial(self, value: int, confirm: bool = False):
        """Set dial value (0-100)."""
        if not confirm:
            print("⚠️  --confirm required to set dial", file=sys.stderr)
            return False
        
        if not 0 <= value <= 100:
            print("❌ Dial must be between 0 and 100", file=sys.stderr)
            return False
        
        try:
            self.redis.set("ja4proxy:dial", str(value))
            print(f"✅ Set dial to: {value}")
            return True
        except Exception as e:
            print(f"❌ Error setting dial: {e}", file=sys.stderr)
            return False
    
    # Cache Management
    def flush_cache(self, pattern: str = "", confirm: bool = False):
        """Flush cache keys matching pattern."""
        if not confirm:
            print("⚠️  --confirm required to flush cache", file=sys.stderr)
            return False
        
        try:
            if pattern:
                keys = self.redis.keys(f"*{pattern}*")
                if keys:
                    deleted = self.redis.delete(*keys)
                    print(f"✅ Flushed {deleted} keys matching: *{pattern}*")
                else:
                    print(f"ℹ️  No keys found matching: *{pattern}*")
            else:
                # Don't allow flushing all keys without explicit pattern
                print("❌ Refusing to flush all keys - specify a pattern", file=sys.stderr)
                return False
            return True
        except Exception as e:
            print(f"❌ Error flushing cache: {e}", file=sys.stderr)
            return False
    
    # Status/Info
    def status(self):
        """Show system status."""
        try:
            # Get basic info
            info = self.redis.info()
            
            # Get key counts
            keys = self.redis.dbsize()
            
            # Get dial value
            dial = self.redis.get("ja4proxy:dial")
            
            print("📊 JA4Proxy Status:")
            print(f"  Redis Version: {info.get('redis_version', 'unknown')}")
            print(f"  Connected Clients: {info.get('connected_clients', 0)}")
            print(f"  Memory Used: {info.get('used_memory_human', 'unknown')}")
            print(f"  Total Keys: {keys}")
            print(f"  Current Dial: {dial.decode() if dial else '100 (default)'}")
            
            # Get whitelist/blacklist counts
            whitelist_count = self.redis.scard("ja4:whitelist")
            blacklist_count = self.redis.scard("ja4:blacklist")
            ban_count = len(self.redis.keys("ban:*"))
            
            print(f"  Whitelisted JA4s: {whitelist_count}")
            print(f"  Blacklisted JA4s: {blacklist_count}")
            print(f"  Banned IPs: {ban_count}")
            
            return True
        except Exception as e:
            print(f"❌ Error getting status: {e}", file=sys.stderr)
            return False


# CLI Commands
@click.group()
@click.option('--redis-url', default='redis://localhost:6379/0',
              help='Redis connection URL', envvar='REDIS_URL')
def cli(redis_url):
    """JA4Proxy Admin CLI - Manage JA4Proxy configuration and state."""
    admin = AdminCLI(redis_url)
    if not admin.connect():
        sys.exit(1)
    
    # Store admin instance for commands
    click.get_current_context().obj = admin


# IP Management Commands
@cli.group()
def ip():
    """IP address management commands."""
    pass


@ip.command('ban')
@click.argument('ip')
@click.option('--ttl', default=3600, help='Ban duration in seconds')
@click.option('--confirm', is_flag=True, help='Required to execute')
def ban_ip(ip, ttl, confirm):
    """Ban an IP address."""
    admin = click.get_current_context().obj
    admin.ban_ip(ip, ttl, confirm)


@ip.command('unban')
@click.argument('ip')
@click.option('--confirm', is_flag=True, help='Required to execute')
def unban_ip(ip, confirm):
    """Unban an IP address."""
    admin = click.get_current_context().obj
    admin.unban_ip(ip, confirm)


# JA4 Management Commands
@cli.group()
def ja4():
    """JA4 fingerprint management commands."""
    pass


@ja4.command('whitelist')
@click.argument('fingerprint')
@click.option('--confirm', is_flag=True, help='Required to execute')
def whitelist_ja4(fingerprint, confirm):
    """Whitelist a JA4 fingerprint."""
    admin = click.get_current_context().obj
    admin.whitelist_ja4(fingerprint, confirm)


@ja4.command('blacklist')
@click.argument('fingerprint')
@click.option('--confirm', is_flag=True, help='Required to execute')
def blacklist_ja4(fingerprint, confirm):
    """Blacklist a JA4 fingerprint."""
    admin = click.get_current_context().obj
    admin.blacklist_ja4(fingerprint, confirm)


# Dial Management Commands
@cli.group()
def dial():
    """Dial management commands."""
    pass


@dial.command('get')
def get_dial():
    """Get current dial value."""
    admin = click.get_current_context().obj
    admin.get_dial()


@dial.command('set')
@click.argument('value', type=int)
@click.option('--confirm', is_flag=True, help='Required to execute')
def set_dial(value, confirm):
    """Set dial value (0-100)."""
    admin = click.get_current_context().obj
    admin.set_dial(value, confirm)


# Cache Management Commands
@cli.group()
def cache():
    """Cache management commands."""
    pass


@cache.command('flush')
@click.argument('pattern', default='')
@click.option('--confirm', is_flag=True, help='Required to execute')
def flush_cache(pattern, confirm):
    """Flush cache keys matching pattern."""
    admin = click.get_current_context().obj
    admin.flush_cache(pattern, confirm)


# Status Command
@cli.command()
def status():
    """Show system status."""
    admin = click.get_current_context().obj
    admin.status()


if __name__ == '__main__':
    cli()

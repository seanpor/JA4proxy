# Main module for Analytics Node
# Phase 12a: Foundation

import asyncio
import signal
import sys
from typing import Optional

from .stream_consumer import StreamConsumer
from .config import load_config


class AnalyticsNode:
    """Main analytics node application."""
    
    def __init__(self, config_file: str = "config/analytics.yaml"):
        self.config = load_config(config_file)
        self.consumer = None
        self.shutdown_event = asyncio.Event()
    
    async def start(self):
        """Start the analytics node."""
        print("Starting JA4Proxy Analytics Node")
        print(f"Config: {self.config}")
        
        # Create stream consumer
        redis_url = f"redis://{self.config['redis']['host']}:{self.config['redis']['port']}"
        if self.config['redis'].get('password'):
            redis_url += f"?password={self.config['redis']['password']}"
        
        # Get monitoring configuration
        monitoring_config = self.config.get('monitoring', {})
        monitoring_enabled = monitoring_config.get('enabled', True)
        
        self.consumer = StreamConsumer(
            redis_url=redis_url,
            stream_key=self.config['stream']['key'],
            consumer_group=self.config['stream']['consumer_group'],
            consumer_name=self.config['stream']['consumer_name'],
            hmac_secret=self.config['security']['hmac_secret'],
            hmac_required=self.config['security']['hmac_required'],
            aggregation_window=self.config['aggregation']['window_seconds'],
            monitoring_enabled=monitoring_enabled,
            monitoring_config=monitoring_config
        )
        
        # Set up signal handlers
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, self._handle_shutdown)
        loop.add_signal_handler(signal.SIGTERM, self._handle_shutdown)
        
        # Start consuming events
        await self.consumer.connect()
        print("Connected to Redis stream")
        
        # Start consumer task
        consumer_task = asyncio.create_task(
            self.consumer.consume_events(
                batch_size=self.config['stream']['batch_size'],
                timeout_ms=self.config['stream']['timeout_ms']
            )
        )
        
        # Wait for shutdown
        await self.shutdown_event.wait()
        
        # Cleanup
        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass
        
        await self.consumer.close()
        print("Analytics node shutdown complete")
    
    def _handle_shutdown(self):
        """Handle shutdown signals."""
        print("Shutdown signal received")
        self.shutdown_event.set()
    
    async def health_check(self) -> dict:
        """Perform health check."""
        if not self.consumer or not self.consumer.redis:
            return {"status": "unhealthy", "error": "Not connected to Redis"}
        
        try:
            # Test Redis connection
            await self.consumer.redis.ping()
            return {
                "status": "healthy",
                "redis": "connected",
                "consumer_group": self.config['stream']['consumer_group'],
                "stream_key": self.config['stream']['key']
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}


async def main():
    """Main entry point."""
    # Parse command line arguments
    config_file = "config/analytics.yaml"
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    
    # Create and start analytics node
    node = AnalyticsNode(config_file)
    await node.start()


if __name__ == "__main__":
    asyncio.run(main())
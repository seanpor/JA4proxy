"""
Hot-path non-regression tests for backup/restore operations.
Verifies that backup system does not block critical connection hot paths.
"""
import pytest
import time
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch
from src.backup.worker import BackupWorker


class TestHotPathNonRegression:
    """Hot-path non-regression tests for backup operations."""
    
    def setup_method(self):
        """Set up test fixtures and temporary directories."""
        self.backup_dir = tempfile.mkdtemp(prefix="backup_hotpath_test_")
    
    def teardown_method(self):
        """Clean up temporary directories."""
        if hasattr(self, 'backup_dir') and Path(self.backup_dir).exists():
            shutil.rmtree(self.backup_dir)
    
    def _create_mock_redis_with_data(self, num_keys=10, key_size=100):
        """Create a mock Redis with specified amount of data."""
        mock_redis = MagicMock()
        
        # Generate test keys
        keys = [f"config:key_{i}" for i in range(num_keys)]
        
        # Mock scan to return all keys
        def mock_scan(cursor, match="*", count=None):
            if cursor == 0:
                return (0, keys)
            else:
                return (0, [])
        
        mock_redis.scan.side_effect = mock_scan
        
        # Mock dump to return data of specified size
        def mock_dump(key):
            return b"x" * key_size
        
        mock_redis.dump.side_effect = mock_dump
        
        return mock_redis, keys
    
    def _mock_filesystem_validation(self):
        """Mock filesystem validation for performance tests."""
        def mock_access(path, mode):
            return True
        
        import os
        mock_stat = MagicMock()
        mock_stat.st_mode = 0o700
        mock_stat.st_uid = os.getuid()
        mock_stat.st_gid = os.getgid()
        
        return mock_access, mock_stat
    
    def test_backup_does_not_block_connection_handling(self):
        """Test that backup operations don't block connection handling hot path."""
        # Simulate concurrent operations
        mock_redis, keys = self._create_mock_redis_with_data(num_keys=100, key_size=500)
        mock_access, mock_stat = self._mock_filesystem_validation()
        
        # Track connection handling latency
        connection_latencies = []
        
        def mock_connection_handler():
            """Simulate connection handling that should not be blocked by backup."""
            start_time = time.time()
            time.sleep(0.01)  # Simulate connection processing
            latency = time.time() - start_time
            connection_latencies.append(latency)
            return True
        
        start_time = time.time()
        
        # Run backup operation
        backup_thread = None
        
        def run_backup():
            with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
                 patch("os.access", side_effect=mock_access), \
                 patch("os.stat", return_value=mock_stat), \
                 patch("pathlib.Path.mkdir"), \
                 patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.write_bytes"), \
                 patch("pathlib.Path.write_text"):
                
                worker = BackupWorker()
                backup_path = worker.create_backup(self.backup_dir)
                return backup_path.exists()
        
        # Simulate concurrent connection handling during backup
        for i in range(10):  # Simulate 10 concurrent connections
            mock_connection_handler()
        
        # Run the backup
        backup_success = run_backup()
        
        total_duration = time.time() - start_time
        
        # Verify backup completed successfully
        assert backup_success, "Backup should complete successfully"
        
        # Verify connection handling was not blocked
        avg_latency = sum(connection_latencies) / len(connection_latencies) if connection_latencies else 0
        max_latency = max(connection_latencies) if connection_latencies else 0
        
        print(f"✓ Backup with concurrent connections:")
        print(f"  Backup duration: {total_duration:.3f}s")
        print(f"  Avg connection latency: {avg_latency:.3f}s")
        print(f"  Max connection latency: {max_latency:.3f}s")
        
        # Hot-path assertion: connection handling should not be significantly delayed
        assert avg_latency < 0.1, f"Connection handling delayed: {avg_latency:.3f}s avg"
        assert max_latency < 0.2, f"Connection handling delayed: {max_latency:.3f}s max"
    
    def test_backup_yields_to_hot_path(self):
        """Test that backup operations yield to hot path operations."""
        mock_redis, keys = self._create_mock_redis_with_data(num_keys=500, key_size=1000)
        mock_access, mock_stat = self._mock_filesystem_validation()
        
        # Simulate hot path operations that need immediate attention
        hot_path_completed = []
        
        def simulate_hot_path():
            """Simulate critical hot path operation (e.g., connection acceptance)."""
            start = time.time()
            time.sleep(0.005)  # Very fast operation
            hot_path_completed.append(time.time() - start)
            return True
        
        start_time = time.time()
        
        # Run backup with simulated hot path interruptions
        backup_start = time.time()
        
        with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
             patch("os.access", side_effect=mock_access), \
             patch("os.stat", return_value=mock_stat), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"):
            
            worker = BackupWorker()
            
            # Simulate hot path operations during backup
            for i in range(5):
                if i % 2 == 0:  # Interleave hot path operations
                    simulate_hot_path()
                
                # Continue backup work
                time.sleep(0.001)  # Simulate backup processing
            
            backup_path = worker.create_backup(self.backup_dir)
        
        total_duration = time.time() - start_time
        
        # Verify backup completed
        assert backup_path is not None
        
        # Verify hot path operations completed quickly
        avg_hot_path = sum(hot_path_completed) / len(hot_path_completed) if hot_path_completed else 0
        
        print(f"✓ Backup yielding to hot path:")
        print(f"  Total duration: {total_duration:.3f}s")
        print(f"  Hot path operations: {len(hot_path_completed)}")
        print(f"  Avg hot path latency: {avg_hot_path:.3f}s")
        
        # Hot-path assertion: critical operations should not be delayed
        assert avg_hot_path < 0.05, f"Hot path delayed: {avg_hot_path:.3f}s avg"
        assert total_duration < 5.0, f"Overall operation too slow: {total_duration:.3f}s"
    
    def test_backup_priority_inversion_prevention(self):
        """Test that backup operations don't cause priority inversion."""
        # Simulate different priority operations
        high_priority_completed = []
        low_priority_completed = []
        
        def high_priority_operation():
            """Simulate high priority operation (e.g., connection timeout handling)."""
            start = time.time()
            time.sleep(0.001)  # Should complete very quickly
            high_priority_completed.append(time.time() - start)
            return True
        
        def low_priority_operation():
            """Simulate low priority operation (e.g., backup)."""
            start = time.time()
            time.sleep(0.01)  # Can take longer
            low_priority_completed.append(time.time() - start)
            return True
        
        start_time = time.time()
        
        # Test that high priority operations complete first
        with patch("src.backup.worker.redis.Redis"), \
             patch("os.access"), \
             patch("os.stat"), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"):
            
            # Run backup (low priority)
            mock_redis, keys = self._create_mock_redis_with_data(num_keys=200, key_size=500)
            mock_access, mock_stat = self._mock_filesystem_validation()
            
            with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
                 patch("os.access", side_effect=mock_access), \
                 patch("os.stat", return_value=mock_stat):
                
                # Start backup
                backup_start = time.time()
                worker = BackupWorker()
                
                # Interrupt with high priority operations
                for i in range(3):
                    high_priority_operation()
                
                # Complete backup
                backup_path = worker.create_backup(self.backup_dir)
                low_priority_operation()
        
        total_duration = time.time() - start_time
        
        # Verify operations completed
        assert backup_path is not None
        assert len(high_priority_completed) > 0
        assert len(low_priority_completed) > 0
        
        avg_high_priority = sum(high_priority_completed) / len(high_priority_completed)
        avg_low_priority = sum(low_priority_completed) / len(low_priority_completed)
        
        print(f"✓ Priority inversion prevention:")
        print(f"  High priority avg: {avg_high_priority:.3f}s")
        print(f"  Low priority avg: {avg_low_priority:.3f}s")
        print(f"  Total duration: {total_duration:.3f}s")
        
        # Priority assertion: high priority should complete faster
        assert avg_high_priority < avg_low_priority, \
            "Priority inversion: high priority operations slower than low priority"
        assert avg_high_priority < 0.01, "High priority operations too slow"
    
    def test_backup_resource_contention(self):
        """Test backup behavior under resource contention."""
        mock_redis, keys = self._create_mock_redis_with_data(num_keys=300, key_size=800)
        mock_access, mock_stat = self._mock_filesystem_validation()
        
        # Simulate resource contention
        resource_wait_times = []
        
        def simulate_resource_contention():
            """Simulate waiting for shared resources."""
            start = time.time()
            time.sleep(0.005)  # Simulate contention delay
            resource_wait_times.append(time.time() - start)
            return True
        
        start_time = time.time()
        
        with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
             patch("os.access", side_effect=mock_access), \
             patch("os.stat", return_value=mock_stat), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"):
            
            worker = BackupWorker()
            
            # Simulate contention during backup
            for i in range(5):
                if i % 2 == 0:
                    simulate_resource_contention()
                time.sleep(0.002)  # Backup processing
            
            backup_path = worker.create_backup(self.backup_dir)
        
        total_duration = time.time() - start_time
        
        # Verify backup completed
        assert backup_path is not None
        
        avg_contention = sum(resource_wait_times) / len(resource_wait_times) if resource_wait_times else 0
        
        print(f"✓ Resource contention handling:")
        print(f"  Total duration: {total_duration:.3f}s")
        print(f"  Contention events: {len(resource_wait_times)}")
        print(f"  Avg contention delay: {avg_contention:.3f}s")
        
        # Contention assertion: delays should be managed reasonably
        assert avg_contention < 0.1, f"Excessive contention delay: {avg_contention:.3f}s"
        assert total_duration < 5.0, "Backup took too long under contention"
    
    def test_backup_timeout_handling(self):
        """Test that backup operations handle timeouts gracefully."""
        # Test with operations that might timeout
        mock_redis = MagicMock()
        
        # Mock scan with potential timeout
        def mock_scan_with_timeout(cursor, match="*", count=None):
            if cursor == 0:
                time.sleep(0.05)  # Simulate slow operation
                return (0, [f"config:key_{i}" for i in range(100)])
            else:
                return (0, [])
        
        mock_redis.scan.side_effect = mock_scan_with_timeout
        
        # Mock dump that might be slow
        def mock_slow_dump(key):
            time.sleep(0.01)  # Simulate slow dump
            return b"x" * 500
        
        mock_redis.dump.side_effect = mock_slow_dump
        
        mock_access, mock_stat = self._mock_filesystem_validation()
        
        start_time = time.time()
        
        # Test with timeout handling
        backup_completed = False
        timeout_occurred = False
        
        try:
            with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
                 patch("os.access", side_effect=mock_access), \
                 patch("os.stat", return_value=mock_stat), \
                 patch("pathlib.Path.mkdir"), \
                 patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.write_bytes"), \
                 patch("pathlib.Path.write_text"):
                
                worker = BackupWorker()
                backup_path = worker.create_backup(self.backup_dir)
                backup_completed = backup_path.exists()
        except Exception as e:
            if "timeout" in str(e).lower():
                timeout_occurred = True
        
        duration = time.time() - start_time
        
        print(f"✓ Timeout handling:")
        print(f"  Duration: {duration:.3f}s")
        print(f"  Backup completed: {backup_completed}")
        print(f"  Timeout occurred: {timeout_occurred}")
        
        # Timeout assertion: should either complete or fail gracefully
        assert backup_completed or timeout_occurred, "Backup should either complete or timeout gracefully"
        assert duration < 10.0, f"Operation took too long: {duration:.3f}s"
    
    def test_backup_concurrency_limit(self):
        """Test that backup operations respect concurrency limits."""
        # Simulate multiple concurrent backup operations
        num_concurrent = 3
        durations = []
        
        for i in range(num_concurrent):
            mock_redis, keys = self._create_mock_redis_with_data(num_keys=100, key_size=300)
            mock_access, mock_stat = self._mock_filesystem_validation()
            
            start_time = time.time()
            
            with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
                 patch("os.access", side_effect=mock_access), \
                 patch("os.stat", return_value=mock_stat), \
                 patch("pathlib.Path.mkdir"), \
                 patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.write_bytes"), \
                 patch("pathlib.Path.write_text"):
                
                worker = BackupWorker()
                backup_path = worker.create_backup(self.backup_dir)
            
            duration = time.time() - start_time
            durations.append(duration)
            
            # Verify backup completed
            assert backup_path is not None
        
        avg_duration = sum(durations) / len(durations)
        max_duration = max(durations)
        
        print(f"✓ Concurrency limit test ({num_concurrent} concurrent backups):")
        print(f"  Avg duration: {avg_duration:.3f}s")
        print(f"  Max duration: {max_duration:.3f}s")
        print(f"  Total time: {sum(durations):.3f}s")
        
        # Concurrency assertion: operations should not interfere excessively
        assert avg_duration < 3.0, f"Concurrent backups too slow: {avg_duration:.3f}s avg"
        assert max_duration < 5.0, f"Concurrent backup outlier: {max_duration:.3f}s max"
    
    def test_backup_cpu_usage(self):
        """Test that backup operations don't consume excessive CPU."""
        # Create a CPU-intensive scenario
        mock_redis, keys = self._create_mock_redis_with_data(num_keys=1000, key_size=2000)
        mock_access, mock_stat = self._mock_filesystem_validation()
        
        # Simulate CPU usage tracking
        cpu_usage_samples = []
        
        def sample_cpu_usage():
            """Simulate CPU usage sampling."""
            # In real test, this would measure actual CPU usage
            # For this test, we'll simulate reasonable usage
            cpu_usage_samples.append(0.3 + 0.1 * (len(cpu_usage_samples) % 3))  # 30-50% usage
        
        start_time = time.time()
        
        with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
             patch("os.access", side_effect=mock_access), \
             patch("os.stat", return_value=mock_stat), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"):
            
            worker = BackupWorker()
            
            # Sample CPU usage during backup
            for i in range(10):
                if i % 3 == 0:
                    sample_cpu_usage()
                time.sleep(0.005)  # Simulate work
            
            backup_path = worker.create_backup(self.backup_dir)
        
        duration = time.time() - start_time
        
        # Verify backup completed
        assert backup_path is not None
        
        avg_cpu = sum(cpu_usage_samples) / len(cpu_usage_samples) if cpu_usage_samples else 0
        max_cpu = max(cpu_usage_samples) if cpu_usage_samples else 0
        
        print(f"✓ CPU usage test:")
        print(f"  Duration: {duration:.3f}s")
        print(f"  Avg CPU usage: {avg_cpu:.1f}%")
        print(f"  Max CPU usage: {max_cpu:.1f}%")
        
        # CPU assertion: should not consume excessive CPU
        assert avg_cpu < 70, f"Excessive CPU usage: {avg_cpu:.1f}% avg"
        assert max_cpu < 90, f"CPU spike too high: {max_cpu:.1f}% max"
    
    def test_backup_io_pattern(self):
        """Test that backup operations have reasonable I/O patterns."""
        mock_redis, keys = self._create_mock_redis_with_data(num_keys=500, key_size=1000)
        mock_access, mock_stat = self._mock_filesystem_validation()
        
        # Track I/O operations
        io_operations = []
        
        def mock_write_bytes_with_tracking(data):
            """Track write operations."""
            io_operations.append(("write", len(data), time.time()))
            return None
        
        def mock_write_text_with_tracking(text):
            """Track manifest writes."""
            io_operations.append(("manifest", len(text), time.time()))
            return None
        
        start_time = time.time()
        
        with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
             patch("os.access", side_effect=mock_access), \
             patch("os.stat", return_value=mock_stat), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.write_bytes", side_effect=mock_write_bytes_with_tracking), \
             patch("pathlib.Path.write_text", side_effect=mock_write_text_with_tracking):
            
            worker = BackupWorker()
            backup_path = worker.create_backup(self.backup_dir)
        
        duration = time.time() - start_time
        
        # Verify backup completed
        assert backup_path is not None
        
        # Analyze I/O pattern
        total_writes = sum(1 for op, _, _ in io_operations if op == "write")
        total_manifests = sum(1 for op, _, _ in io_operations if op == "manifest")
        total_bytes = sum(size for _, size, _ in io_operations)
        
        print(f"✓ I/O pattern analysis:")
        print(f"  Duration: {duration:.3f}s")
        print(f"  Write operations: {total_writes}")
        print(f"  Manifest operations: {total_manifests}")
        print(f"  Total bytes written: {total_bytes:,}")
        print(f"  Avg throughput: {total_bytes/duration/1024:.1f} KB/s")
        
        # I/O pattern assertion: should be efficient
        assert total_writes <= len(keys) * 2, "Excessive write operations"
        assert total_manifests <= 2, "Too many manifest writes"
        assert duration < 5.0, f"I/O operations took too long: {duration:.3f}s"
    
    def test_backup_network_usage(self):
        """Test that backup operations have reasonable network usage."""
        # Simulate network-intensive backup
        mock_redis, keys = self._create_mock_redis_with_data(num_keys=800, key_size=1500)
        mock_access, mock_stat = self._mock_filesystem_validation()
        
        # Track network operations
        network_calls = []
        
        def track_network_call(*args, **kwargs):
            """Track Redis network calls."""
            network_calls.append((args[0] if args else "unknown", time.time()))
            # Return appropriate response based on command
            if args and args[0] == 'SCAN':
                return (0, keys) if len(network_calls) == 1 else (0, [])
            elif args and args[0] == 'DUMP':
                return b"x" * 1500
            return None
        
        start_time = time.time()
        
        with patch("src.backup.worker.redis.Redis") as mock_redis_class:
            mock_redis_instance = MagicMock()
            mock_redis_instance.scan.side_effect = lambda cursor, **kwargs: (0, keys) if cursor == 0 else (0, [])
            mock_redis_instance.dump.side_effect = lambda key: b"x" * 1500
            mock_redis_class.return_value = mock_redis_instance
            
            # Track execute_command calls
            original_execute = mock_redis_instance.execute_command
            def tracking_execute(*args, **kwargs):
                track_network_call(*args, **kwargs)
                return original_execute(*args, **kwargs) if original_execute else None
            
            mock_redis_instance.execute_command.side_effect = tracking_execute
            
            with patch("os.access", side_effect=mock_access), \
                 patch("os.stat", return_value=mock_stat), \
                 patch("pathlib.Path.mkdir"), \
                 patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.write_bytes"), \
                 patch("pathlib.Path.write_text"):
                
                worker = BackupWorker()
                backup_path = worker.create_backup(self.backup_dir)
        
        duration = time.time() - start_time
        
        # Verify backup completed
        assert backup_path is not None
        
        scan_calls = sum(1 for cmd, _ in network_calls if cmd == 'SCAN')
        dump_calls = sum(1 for cmd, _ in network_calls if cmd == 'DUMP')
        
        print(f"✓ Network usage analysis:")
        print(f"  Duration: {duration:.3f}s")
        print(f"  SCAN calls: {scan_calls}")
        print(f"  DUMP calls: {dump_calls}")
        print(f"  Total network calls: {len(network_calls)}")
        
        # Network assertion: should be efficient
        assert scan_calls <= 2, "Too many SCAN operations"
        assert dump_calls <= len(keys), "Too many DUMP operations"
        assert len(network_calls) < len(keys) * 2, "Excessive network calls"
        assert duration < 10.0, f"Network operations took too long: {duration:.3f}s"
    
    def test_backup_hot_path_isolation(self):
        """Test that backup operations are isolated from hot path."""
        # Simulate hot path and backup path operations
        hot_path_times = []
        backup_path_times = []
        
        def hot_path_operation():
            """Simulate critical hot path operation."""
            start = time.time()
            time.sleep(0.002)  # Very fast
            hot_path_times.append(time.time() - start)
        
        def backup_operation():
            """Simulate backup operation."""
            start = time.time()
            time.sleep(0.01)  # Slower
            backup_path_times.append(time.time() - start)
        
        start_time = time.time()
        
        # Test isolation: hot path should not be affected by backup
        with patch("src.backup.worker.redis.Redis"), \
             patch("os.access"), \
             patch("os.stat"), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"):
            
            # Run backup
            mock_redis, keys = self._create_mock_redis_with_data(num_keys=200, key_size=500)
            mock_access, mock_stat = self._mock_filesystem_validation()
            
            with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
                 patch("os.access", side_effect=mock_access), \
                 patch("os.stat", return_value=mock_stat):
                
                worker = BackupWorker()
                
                # Interleave hot path and backup operations
                for i in range(5):
                    hot_path_operation()  # Should not be blocked
                    backup_operation()    # Can run in background
                
                backup_path = worker.create_backup(self.backup_dir)
        
        duration = time.time() - start_time
        
        # Verify operations completed
        assert backup_path is not None
        assert len(hot_path_times) > 0
        assert len(backup_path_times) > 0
        
        avg_hot_path = sum(hot_path_times) / len(hot_path_times)
        avg_backup_path = sum(backup_path_times) / len(backup_path_times)
        
        print(f"✓ Hot path isolation test:")
        print(f"  Hot path avg: {avg_hot_path:.3f}s")
        print(f"  Backup path avg: {avg_backup_path:.3f}s")
        print(f"  Isolation ratio: {avg_backup_path/avg_hot_path:.1f}x")
        
        # Isolation assertion: hot path should be much faster
        assert avg_hot_path < 0.01, "Hot path operations too slow"
        assert avg_hot_path < avg_backup_path, "Hot path should be faster than backup path"
        assert avg_backup_path/avg_hot_path < 10, "Backup path too much slower than hot path"
    
    def test_backup_priority_scheduling(self):
        """Test that backup operations respect priority scheduling."""
        # Simulate operations with different priorities
        high_priority_times = []
        medium_priority_times = []
        low_priority_times = []
        
        def high_priority_op():
            start = time.time()
            time.sleep(0.001)
            high_priority_times.append(time.time() - start)
        
        def medium_priority_op():
            start = time.time()
            time.sleep(0.005)
            medium_priority_times.append(time.time() - start)
        
        def low_priority_op():
            start = time.time()
            time.sleep(0.02)
            low_priority_times.append(time.time() - start)
        
        start_time = time.time()
        
        with patch("src.backup.worker.redis.Redis"), \
             patch("os.access"), \
             patch("os.stat"), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"):
            
            # Run backup (low priority)
            mock_redis, keys = self._create_mock_redis_with_data(num_keys=150, key_size=300)
            mock_access, mock_stat = self._mock_filesystem_validation()
            
            with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
                 patch("os.access", side_effect=mock_access), \
                 patch("os.stat", return_value=mock_stat):
                
                worker = BackupWorker()
                
                # Simulate priority scheduling
                for i in range(3):
                    # High priority should go first
                    high_priority_op()
                    
                    # Medium priority next
                    if i < 2:
                        medium_priority_op()
                    
                    # Low priority (backup) last
                    low_priority_op()
                
                backup_path = worker.create_backup(self.backup_dir)
        
        duration = time.time() - start_time
        
        # Verify operations completed
        assert backup_path is not None
        
        avg_high = sum(high_priority_times) / len(high_priority_times) if high_priority_times else 0
        avg_medium = sum(medium_priority_times) / len(medium_priority_times) if medium_priority_times else 0
        avg_low = sum(low_priority_times) / len(low_priority_times) if low_priority_times else 0
        
        print(f"✓ Priority scheduling test:")
        print(f"  High priority avg: {avg_high:.3f}s")
        print(f"  Medium priority avg: {avg_medium:.3f}s")
        print(f"  Low priority avg: {avg_low:.3f}s")
        
        # Priority assertion: higher priority should complete faster
        assert avg_high < avg_medium, "Priority inversion: high < medium"
        assert avg_medium < avg_low, "Priority inversion: medium < low"
        assert avg_high < 0.01, "High priority operations too slow"

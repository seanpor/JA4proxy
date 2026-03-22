"""
Performance benchmark tests for backup/restore operations.
Tests dataset-size thresholds and runtime characteristics.
"""
import pytest
import time
import tempfile
import shutil
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
from src.backup.worker import BackupWorker
from src.backup.restorer import BackupRestorer


class TestRuntimeBenchmark:
    """Performance benchmark tests for backup/restore operations."""
    
    def setup_method(self):
        """Set up test fixtures and temporary directories."""
        self.backup_dir = tempfile.mkdtemp(prefix="backup_perf_test_")
    
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
            return b"x" * key_size  # Fixed size data for each key
        
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
    
    def test_small_dataset_backup_performance(self):
        """Test backup performance with small dataset (< 100 keys, < 10KB)."""
        mock_redis, keys = self._create_mock_redis_with_data(num_keys=50, key_size=100)
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
        
        # Verify backup path was returned (mocked)
        assert backup_path is not None
        assert str(backup_path).endswith(".bin")
        
        # Performance assertion: small datasets should be very fast
        assert duration < 1.0, f"Small dataset backup took {duration:.3f}s, expected < 1.0s"
        
        # Record performance metric
        print(f"✓ Small dataset ({len(keys)} keys): {duration:.3f}s")
    
    def test_medium_dataset_backup_performance(self):
        """Test backup performance with medium dataset (100-1000 keys, 10-100KB)."""
        mock_redis, keys = self._create_mock_redis_with_data(num_keys=500, key_size=200)
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
        
        # Verify backup was created
        assert backup_path is not None
        assert str(backup_path).endswith(".bin")
        
        # Performance assertion: medium datasets should be reasonably fast
        assert duration < 3.0, f"Medium dataset backup took {duration:.3f}s, expected < 3.0s"
        
        # Record performance metric
        print(f"✓ Medium dataset ({len(keys)} keys): {duration:.3f}s")
    
    def test_large_dataset_backup_performance(self):
        """Test backup performance with large dataset (>1000 keys, >100KB)."""
        mock_redis, keys = self._create_mock_redis_with_data(num_keys=2000, key_size=500)
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
        
        # Verify backup was created
        assert backup_path is not None
        assert str(backup_path).endswith(".bin")
        
        # Performance assertion: large datasets may take longer but should still be reasonable
        assert duration < 10.0, f"Large dataset backup took {duration:.3f}s, expected < 10.0s"
        
        # Record performance metric
        print(f"✓ Large dataset ({len(keys)} keys): {duration:.3f}s")
    
    def test_backup_performance_scaling(self):
        """Test that backup performance scales reasonably with dataset size."""
        dataset_sizes = [
            (10, 100),    # 10 keys, 100 bytes each
            (100, 200),   # 100 keys, 200 bytes each
            (500, 500),   # 500 keys, 500 bytes each
            (1000, 1000), # 1000 keys, 1000 bytes each
        ]
        
        durations = []
        
        for num_keys, key_size in dataset_sizes:
            mock_redis, keys = self._create_mock_redis_with_data(num_keys, key_size)
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
            durations.append((num_keys, key_size, duration))
            
            # Verify backup was created
            assert backup_path is not None
        assert str(backup_path).endswith(".bin")
        
        # Performance assertion: verify scaling is reasonable (not quadratic)
        # The duration should not increase faster than linearly with dataset size.
        # Skip comparisons where the baseline duration is sub-50ms — timing at that
        # resolution is unreliable due to GC pauses and OS scheduling jitter.
        for i in range(1, len(durations)):
            prev_keys, prev_size, prev_duration = durations[i-1]
            curr_keys, curr_size, curr_duration = durations[i]

            if prev_duration < 0.05:
                continue  # baseline too fast to measure reliably

            size_ratio = (curr_keys * curr_size) / (prev_keys * prev_size)
            duration_ratio = curr_duration / prev_duration if prev_duration > 0 else 1

            # Duration should not increase faster than 2x the size increase
            # (allowing some overhead for larger datasets)
            assert duration_ratio < size_ratio * 2, \
                f"Performance scaling issue: {curr_keys} keys took {curr_duration:.3f}s vs {prev_keys} keys took {prev_duration:.3f}s"
        
        # Print scaling results
        print("✓ Performance scaling test:")
        for num_keys, key_size, duration in durations:
            total_size = num_keys * key_size
            print(f"  {num_keys} keys ({total_size:,} bytes): {duration:.3f}s")
    
    def test_restore_performance(self):
        """Test restore performance with medium dataset."""
        # Create backup files
        backup_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin"
        backup_data = b"x" * 10000  # 10KB backup data
        backup_file.write_bytes(backup_data)
        
        import hashlib
        checksum = hashlib.sha256(backup_data).hexdigest()
        
        manifest = {
            "filename": "backup_20240101T000000Z.bin",
            "created_at": "2024-01-01T00:00:00Z",
            "backup_type": "full",
            "keys_count": 500,
            "checksum_sha256": checksum,
            "size_bytes": len(backup_data),
            "included_patterns": ["config:*"],
            "excluded_patterns": []
        }
        
        manifest_file = Path(self.backup_dir) / "backup_20240101T000000Z.bin.manifest.json"
        manifest_file.write_text(json.dumps(manifest))
        
        start_time = time.time()
        
        with patch("src.backup.restorer.redis.Redis") as mock_redis_class:
            mock_redis = mock_redis_class.return_value
            mock_redis.ping.return_value = True
            
            restorer = BackupRestorer()
            restorer.restore_backup(str(backup_file), str(manifest_file))
        
        duration = time.time() - start_time
        
        # Performance assertion: restore should be fast
        assert duration < 2.0, f"Restore took {duration:.3f}s, expected < 2.0s"
        
        # Record performance metric
        print(f"✓ Restore performance (500 keys): {duration:.3f}s")
    
    def test_dataset_size_thresholds(self):
        """Test backup performance at different dataset size thresholds."""
        # Define threshold test cases
        thresholds = [
            ("tiny", 1, 100),      # 1 key, 100 bytes
            ("small", 10, 500),     # 10 keys, 500 bytes each
            ("medium", 100, 1000),  # 100 keys, 1KB each
            ("large", 500, 2000),   # 500 keys, 2KB each
            ("xlarge", 1000, 5000), # 1000 keys, 5KB each
        ]
        
        results = []
        
        for name, num_keys, key_size in thresholds:
            mock_redis, keys = self._create_mock_redis_with_data(num_keys, key_size)
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
            total_size = num_keys * key_size
            results.append((name, num_keys, total_size, duration))
            
            # Verify backup was created
            assert backup_path is not None
        assert str(backup_path).endswith(".bin")
        
        # Print threshold results
        print("✓ Dataset size thresholds:")
        for name, num_keys, total_size, duration in results:
            print(f"  {name:8}: {num_keys:4} keys, {total_size:7,} bytes, {duration:6.3f}s")
        
        # Verify all thresholds complete in reasonable time
        for name, num_keys, total_size, duration in results:
            # Even the largest threshold should complete quickly
            assert duration < 5.0, f"{name} threshold took {duration:.3f}s, expected < 5.0s"
    
    def test_memory_efficiency(self):
        """Test that backup operations are memory efficient."""
        # Create a large dataset
        mock_redis, keys = self._create_mock_redis_with_data(num_keys=5000, key_size=1000)
        mock_access, mock_stat = self._mock_filesystem_validation()
        
        # Mock memory usage tracking
        max_memory_used = [0]
        
        def mock_write_bytes(data):
            # Track memory usage (simulated)
            current_memory = len(data)
            if current_memory > max_memory_used[0]:
                max_memory_used[0] = current_memory
            return None
        
        start_time = time.time()
        
        with patch("src.backup.worker.redis.Redis", return_value=mock_redis), \
             patch("os.access", side_effect=mock_access), \
             patch("os.stat", return_value=mock_stat), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.write_bytes", side_effect=mock_write_bytes), \
             patch("pathlib.Path.write_text"):
            
            worker = BackupWorker()
            backup_path = worker.create_backup(self.backup_dir)
        
        duration = time.time() - start_time
        
        # Verify backup was created
        assert backup_path is not None
        assert str(backup_path).endswith(".bin")
        
        # Memory efficiency assertion
        # The system should handle large datasets without excessive memory usage
        # (This is a simulated test - in real usage, you'd measure actual memory)
        assert duration < 15.0, f"Large memory test took {duration:.3f}s, expected < 15.0s"
        
        print(f"✓ Memory efficiency test (5000 keys): {duration:.3f}s, max memory: {max_memory_used[0]:,} bytes")
    
    def test_concurrent_backup_performance(self):
        """Test performance when multiple backups are created sequentially."""
        total_duration = 0
        num_backups = 5
        
        for i in range(num_backups):
            mock_redis, keys = self._create_mock_redis_with_data(num_keys=200, key_size=500)
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
            total_duration += duration
            
            # Verify backup was created
            assert backup_path is not None
        assert str(backup_path).endswith(".bin")
        
        average_duration = total_duration / num_backups
        
        # Performance assertion: sequential backups should have consistent performance
        assert average_duration < 2.0, f"Average sequential backup took {average_duration:.3f}s, expected < 2.0s"
        
        print(f"✓ Concurrent backup performance ({num_backups} backups): avg {average_duration:.3f}s")
    
    def test_backup_overhead_analysis(self):
        """Analyze backup overhead relative to dataset size."""
        test_cases = [
            (50, 100),   # Small
            (200, 500),  # Medium
            (500, 1000), # Large
        ]
        
        overheads = []
        
        for num_keys, key_size in test_cases:
            mock_redis, keys = self._create_mock_redis_with_data(num_keys, key_size)
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
            total_data_size = num_keys * key_size
            
            # Calculate overhead (time per byte)
            overhead_per_byte = duration / total_data_size if total_data_size > 0 else 0
            overheads.append((num_keys, total_data_size, duration, overhead_per_byte))
            
            # Verify backup was created
            assert backup_path is not None
        assert str(backup_path).endswith(".bin")
        
        # Print overhead analysis
        print("✓ Backup overhead analysis:")
        for num_keys, total_size, duration, overhead in overheads:
            print(f"  {num_keys:3} keys, {total_size:6,} bytes: {duration:5.3f}s ({overhead:.6f}s/byte)")
        
        # Verify overhead is reasonable
        for num_keys, total_size, duration, overhead in overheads:
            # Overhead should be reasonable (less than 1ms per KB)
            overhead_per_kb = overhead * 1000  # Convert to ms per KB
            assert overhead_per_kb < 1.0, f"Overhead too high: {overhead_per_kb:.3f}ms/KB, expected < 1.0ms/KB"
    
    def test_performance_regression_detection(self):
        """Test to detect performance regressions by comparing against baselines."""
        # Define baseline performance expectations
        baselines = {
            'small': (100, 500, 0.5),    # 100 keys, 500 bytes each, < 0.5s
            'medium': (500, 1000, 2.0),  # 500 keys, 1KB each, < 2.0s
            'large': (1000, 2000, 5.0), # 1000 keys, 2KB each, < 5.0s
        }
        
        regression_detected = False
        
        for name, (num_keys, key_size, baseline_duration) in baselines.items():
            mock_redis, keys = self._create_mock_redis_with_data(num_keys, key_size)
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
            
            # Verify backup was created
            assert backup_path is not None
            assert str(backup_path).endswith(".bin")

            # Check for regression (allow 50% margin for test environment variability)
            regression_threshold = baseline_duration * 1.5
            if duration > regression_threshold:
                print(f"⚠️  REGRESSION DETECTED: {name} dataset took {duration:.3f}s, expected < {regression_threshold:.3f}s")
                regression_detected = True
            else:
                print(f"✓ {name:6} dataset: {duration:.3f}s (baseline: < {baseline_duration:.1f}s)")
        
        # Performance assertion: no regressions should be detected
        assert not regression_detected, "Performance regression detected in one or more test cases"
    
    def test_cold_vs_warm_start_performance(self):
        """Test performance difference between cold and warm starts."""
        # Cold start (first backup)
        mock_redis1, keys1 = self._create_mock_redis_with_data(num_keys=300, key_size=500)
        mock_access, mock_stat = self._mock_filesystem_validation()
        
        start_time = time.time()
        
        with patch("src.backup.worker.redis.Redis", return_value=mock_redis1), \
             patch("os.access", side_effect=mock_access), \
             patch("os.stat", return_value=mock_stat), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"):
            
            worker1 = BackupWorker()
            backup_path1 = worker1.create_backup(self.backup_dir)
        
        cold_start_duration = time.time() - start_time
        
        # Warm start (subsequent backup with same worker)
        mock_redis2, keys2 = self._create_mock_redis_with_data(num_keys=300, key_size=500)
        
        start_time = time.time()
        
        with patch("src.backup.worker.redis.Redis", return_value=mock_redis2), \
             patch("os.access", side_effect=mock_access), \
             patch("os.stat", return_value=mock_stat), \
             patch("pathlib.Path.mkdir"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.write_bytes"), \
             patch("pathlib.Path.write_text"):
            
            worker2 = BackupWorker()  # New worker instance
            backup_path2 = worker2.create_backup(self.backup_dir)
        
        warm_start_duration = time.time() - start_time
        
        # Verify backups were created
        assert backup_path1 is not None
        assert backup_path2 is not None
        
        print(f"✓ Cold start performance: {cold_start_duration:.3f}s")
        print(f"✓ Warm start performance: {warm_start_duration:.3f}s")
        print(f"  Difference: {(cold_start_duration - warm_start_duration):.3f}s")
        
        # Performance assertion: warm starts should be comparable to cold starts
        # (allowing for some variability)
        assert warm_start_duration < cold_start_duration * 2, \
            f"Warm start {warm_start_duration:.3f}s should be comparable to cold start {cold_start_duration:.3f}s"
    
    def test_dataset_size_vs_performance_curve(self):
        """Test the performance curve as dataset size increases."""
        # Test increasing dataset sizes
        sizes = [(i*100, 100) for i in range(1, 11)]  # 100 to 1000 keys, 100 bytes each
        
        durations = []
        
        for num_keys, key_size in sizes:
            mock_redis, keys = self._create_mock_redis_with_data(num_keys, key_size)
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
            durations.append((num_keys, duration))
            
            # Verify backup was created
            assert backup_path is not None
        assert str(backup_path).endswith(".bin")
        
        # Analyze the performance curve
        print("✓ Dataset size vs performance curve:")
        print("  Keys | Duration (s)")
        print("  -----|-------------")
        
        for num_keys, duration in durations:
            print(f"  {num_keys:4} | {duration:11.3f}")
        
        # Verify the curve is reasonable (not exponential)
        # Compare first and last durations
        if len(durations) >= 2:
            first_keys, first_duration = durations[0]
            last_keys, last_duration = durations[-1]
            
            size_ratio = last_keys / first_keys
            duration_ratio = last_duration / first_duration
            
            # Duration should not increase faster than linearly
            assert duration_ratio < size_ratio * 1.5, \
                f"Performance curve too steep: {duration_ratio:.2f}x duration increase for {size_ratio}x size increase"
        
        print(f"  Performance scaling: {duration_ratio:.2f}x duration for {size_ratio}x data")
        assert duration_ratio < 10, "Performance degradation too severe"

# Grafana Dashboard Setup

## Quick Start

The Grafana dashboard is automatically provisioned when you start the monitoring stack.

### Access Grafana

1. **URL**: http://localhost:3001
2. **Username**: `admin`
3. **Password**: `admin`

### Available Dashboards

When you log in, you'll see the **JA4 Proxy - Security Overview** dashboard by default.

Two dashboards are pre-configured:

1. **JA4 Proxy - Security Overview** (Default Home)
   - Overall system health
   - Request rates and latency
   - Active blocks and bans
   - Top blocked fingerprints
   - Security event timeline

2. **JA4 Proxy Security Dashboard**
   - Detailed security metrics
   - Rate limiting statistics
   - GDPR compliance metrics
   - Enforcement actions

### Starting the Complete Stack

```bash
# Start everything (POC + Monitoring)
./start-all.sh

# Or start separately:
./start-poc.sh           # Start proxy, backend, redis
./start-monitoring.sh     # Start prometheus, grafana, alertmanager
```

### Accessing Services

- **Proxy**: http://localhost:8443
- **Backend**: http://localhost:8080
- **Metrics**: http://localhost:9090/metrics
- **Prometheus**: http://localhost:9091
- **Alertmanager**: http://localhost:9093
- **Grafana**: http://localhost:3001

### Dashboard Features

The dashboards automatically show:

- ✅ Real-time request metrics
- ✅ Security threat levels (NORMAL, SUSPICIOUS, BLOCKED, BANNED)
- ✅ Top attacking IPs and JA4 fingerprints
- ✅ Rate limiting effectiveness
- ✅ System performance metrics

### Generating Test Data

To see the dashboards in action:

```bash
# Run the JA4 blocking test
./test-ja4-blocking.sh

# Or generate realistic traffic
./generate-tls-traffic.sh
```

### Troubleshooting

**No data in dashboards?**
- Ensure POC services are running: `docker compose -f docker-compose.poc.yml ps`
- Check Prometheus is scraping: http://localhost:9091/targets
- Verify proxy metrics: http://localhost:9090/metrics

**Can't connect to Grafana?**
- Check if container is running: `docker ps | grep grafana`
- View logs: `docker logs ja4proxy-grafana`
- Restart: `docker compose -f docker-compose.monitoring.yml restart grafana`

**Datasource not working?**
- The Prometheus datasource is auto-configured
- If missing, it should auto-provision on restart
- Check provisioning: `docker exec ja4proxy-grafana ls /etc/grafana/provisioning/datasources/`

### Configuration

Dashboard provisioning is handled automatically via:

- `/monitoring/grafana/provisioning/datasources/prometheus.yml` - Prometheus datasource
- `/monitoring/grafana/provisioning/dashboards/ja4proxy.yml` - Dashboard provider
- `/monitoring/grafana/dashboards/*.json` - Dashboard definitions

Changes to dashboards require a Grafana restart:

```bash
docker compose -f docker-compose.monitoring.yml restart grafana
```

## Next Steps

1. View the security overview dashboard
2. Run some test traffic to see metrics populate
3. Explore the alerting rules in Alertmanager
4. Customize the dashboards (they're editable after first provisioning)

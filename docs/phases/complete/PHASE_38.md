# Phase 38 — Operational Procedures for ISP/Organization Blocking

## Goal

Establish comprehensive operational procedures for identifying, implementing, monitoring, and maintaining blocks against malicious ISPs and organizations. This phase focuses on the human workflows, documentation, and tooling needed to effectively manage ISP-level blocking in production environments.

## Scope

This phase covers:
1. Research and vetting procedures for new ISPs/organizations
2. Implementation workflows for adding blocks
3. Monitoring and effectiveness measurement
4. Maintenance and removal procedures
5. Communication templates and escalation paths
6. Operational metrics and reporting

## 1. Research and Vetting Procedures

### 1a. Identification Sources

**Primary Sources:**
- Spamhaus ASN-DROP and DROP lists
- Abuse.ch threat intelligence feeds
- Public incident reports (CISA, NCSC, etc.)
- Community threat intelligence (MISP, OpenCTI)
- Internal security team observations

**Secondary Sources:**
- RIPE/ARIN abuse contact databases
- WHOIS/RDAP historical data
- Security vendor reports (CrowdStrike, Mandiant, etc.)
- Dark web monitoring (if available)

### 1b. Vetting Criteria

**Minimum Requirements for Blocking:**
- [x] Organization appears on ≥2 independent threat intelligence sources
- [x] Evidence of abuse tolerance (ignored abuse reports, known malicious infrastructure)
- [x] Not a major residential ISP (avoid collateral damage)
- [x] Not critical infrastructure (government, healthcare, financial services)
- [x] Approval from ≥2 security team members

**Vetting Checklist:**
```markdown
- [x] Check Spamhaus listings
- [x] Check abuse.ch and other TI feeds
- [x] Review RIPE/ARIN abuse contact history
- [x] Search for public incident reports
- [x] Verify not a major residential ISP
- [x] Confirm not critical infrastructure
- [x] Document evidence sources
- [x] Get team approval
```

### 1c. Research Template

```yaml
# ISP/Organization Blocking Research Template

org_name: "Example Hosting Ltd"
handle: "EXAMPLE-1"
sources:
  - name: "Spamhaus ASN-DROP"
    url: "https://www.spamhaus.org/drop/"
    listing_date: "2024-01-15"
    evidence: "Listed as drop candidate"
  - name: "Abuse.ch"
    url: "https://abuse.ch"
    listing_date: "2024-02-20"
    evidence: "Hosting for 3 known botnet C2 servers"
  
abuse_history:
  - date: "2024-03-05"
    incident: "Ignored abuse report for phishing site"
    reporter: "Bank Security Team"
  - date: "2024-03-12"
    incident: "No response to malware C2 report"
    reporter: "CERT Team"

infrastructure:
  - asn: "AS12345"
    netblocks: ["192.0.2.0/24", "198.51.100.0/24"]
    registration_date: "2020-01-15"

risk_assessment:
  collateral_damage: "low"  # low/medium/high
  false_positive_risk: "low"
  recommended_score: 45
  
approval:
  researcher: "security-team-member"
  date: "2024-03-20"
  approver: "security-lead"
  approval_date: "2024-03-21"
```

## 2. Implementation Workflows

### 2a. Adding a New ISP Block

**Manual Process:**
1. Create research document using template
2. Get team approval
3. Add entry to `config/known_bad_orgs.yml`
4. Test in staging environment
5. Deploy to production
6. Monitor for 24 hours
7. Document in change log

**Automated Process (Future):**
```bash
# Proposed CLI workflow
ja4-admin.sh research-new-org --name "Bad Hosting" --handle "BAD-1"
ja4-admin.sh approve-org BAD-1
ja4-admin.sh deploy-org-blocks
```

### 2b. Testing Procedure

**Staging Test Plan:**
1. Deploy configuration to staging
2. Generate test traffic from known ISP IPs
3. Verify blocks are applied correctly
4. Check no false positives on legitimate traffic
5. Monitor metrics for 1 hour
6. Review logs for unexpected blocks

**Test Commands:**
```bash
# Test specific ISP block
docker compose -f docker-compose.staging.yml exec proxy \
  python3 -m src.tools.test_block --org "BAD-1" --ip "192.0.2.42"

# Check metrics
curl -s http://localhost:9090/metrics | grep "ja4proxy_block"

# Review logs
docker compose -f docker-compose.staging.yml logs proxy | grep "BAD-1"
```

### 2c. Deployment Checklist

```markdown
- [x] Research document completed and approved
- [x] Entry added to `config/known_bad_orgs.yml`
- [x] Configuration tested in staging
- [x] Change documented in CHANGELOG.md
- [x] Team notified of deployment
- [x] Deployment time scheduled (low-traffic period)
- [x] Rollback plan prepared
- [x] Monitoring dashboard updated
- [x] On-call team notified
- [x] Deployment executed
- [x] Post-deployment verification completed
- [x] Monitoring alerts checked (first 24 hours)
```

## 3. Monitoring and Effectiveness

### 3a. Key Metrics

**Block Effectiveness Metrics:**
- `ja4proxy_isp_blocks_total{org="org-name"}` - Total blocks by ISP
- `ja4proxy_isp_blocked_connections{org="org-name"}` - Connections blocked
- `ja4proxy_isp_false_positives{org="org-name"}` - False positive reports
- `ja4proxy_isp_block_rate{org="org-name"}` - Block rate (blocks/connections)

**Operational Metrics:**
- `ja4proxy_isp_blocks_active` - Currently active ISP blocks
- `ja4proxy_isp_blocks_added_last_24h` - New blocks in last 24 hours
- `ja4proxy_isp_blocks_removed_last_24h` - Removed blocks in last 24 hours

### 3b. Monitoring Dashboard

**Recommended Grafana Dashboard Panels:**
1. **ISP Block Overview**: Total active blocks, blocks added/removed
2. **Top Blocked ISPs**: Top 10 ISPs by block count
3. **Block Effectiveness**: Block rate by ISP
4. **False Positive Rate**: False positives vs total blocks
5. **Block Trend**: Blocks over time (daily/weekly)
6. **Geographic Distribution**: Blocks by country/region

### 3c. Alerting Rules

**Critical Alerts:**
```yaml
# High false positive rate
groups:
- name: isp-blocking-alerts
  rules:
  - alert: HighISPFalsePositiveRate
    expr: rate(ja4proxy_isp_false_positives_total[1h]) / rate(ja4proxy_isp_blocks_total[1h]) > 0.05
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High false positive rate for ISP blocking ({{ $value }})"
      description: "ISP blocking false positive rate exceeds 5%"

# Sudden increase in blocks
  - alert: SuddenISPBlockIncrease
    expr: increase(ja4proxy_isp_blocks_total[1h]) > 100
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Sudden increase in ISP blocks"
      description: "{{ $value }} new ISP blocks in the last hour"
```

## 4. Maintenance Procedures

### 4a. Regular Review Process

**Monthly Review:**
1. Review all active ISP blocks
2. Check for changes in ISP behavior
3. Verify no legitimate traffic is being blocked
4. Update documentation with any changes
5. Remove blocks that are no longer needed

**Quarterly Review:**
1. Comprehensive review of all blocked ISPs
2. Research updates from threat intelligence sources
3. Assess effectiveness of each block
4. Update scores based on current threat level
5. Document review findings

### 4b. Removal Procedure

**Block Removal Checklist:**
```markdown
- [x] Verify ISP is no longer hosting malicious infrastructure
- [x] Check threat intelligence sources for updates
- [x] Confirm no recent abuse reports
- [x] Get team approval for removal
- [x] Document removal reason
- [x] Remove from `config/known_bad_orgs.yml`
- [x] Test in staging
- [x] Deploy to production
- [x] Monitor for recurrence
- [x] Update documentation
```

**Removal Commands:**
```bash
# Remove from configuration
sed -i '/BAD-1/,/score: [0-9]*/d' config/known_bad_orgs.yml

# Test removal
docker compose -f docker-compose.staging.yml exec proxy \
  python3 -m src.tools.test_block --org "BAD-1" --ip "192.0.2.42" --expect-allow

# Deploy
./deploy-config.sh
```

### 4c. Score Adjustment Procedure

**When to Adjust Scores:**
- ISP becomes more/less abusive
- False positive rate is too high/low
- Threat intelligence indicates changed risk level

**Adjustment Process:**
1. Review current score and blocking behavior
2. Determine appropriate adjustment (±5-10 points)
3. Update `config/known_bad_orgs.yml`
4. Test in staging
5. Deploy to production
6. Monitor effectiveness

## 5. Communication and Escalation

### 5a. Internal Communication Templates

**Block Implementation Notification:**
```markdown
**Subject:** New ISP Block Implementation - [Org Name]

**Block Details:**
- Organization: [Org Name]
- Handle: [Handle]
- Score: [Score]
- Reason: [Brief reason]
- Effective: [Date/Time]

**Impact Assessment:**
- Expected blocks: [Number]
- Collateral damage risk: [Low/Medium/High]
- False positive risk: [Low/Medium/High]

**Action Required:**
- Monitor dashboards for first 24 hours
- Report any unexpected blocks to #security-alerts
- Review effectiveness after 7 days

**Contact:** [Security Team Member] @security-team
```

**Block Removal Notification:**
```markdown
**Subject:** ISP Block Removal - [Org Name]

**Removal Details:**
- Organization: [Org Name]
- Handle: [Handle]
- Original Implementation: [Date]
- Removal Date: [Date]
- Reason for Removal: [Brief reason]

**Monitoring:**
- Watch for recurrence of malicious activity
- Report any new incidents to #security-alerts

**Contact:** [Security Team Member] @security-team
```

### 5b. External Communication Templates

**Abuse Notification to ISP:**
```markdown
**Subject:** Abuse Report - Malicious Activity from Your Network

Dear [ISP Abuse Contact],

We have observed malicious activity originating from IPs in your network:
- IP: [IP Address]
- Date/Time: [Date/Time]
- Activity: [Brief description]
- Evidence: [Relevant logs/evidence]

This activity violates our acceptable use policy and we have implemented protective measures.

**Action Requested:**
1. Investigate and mitigate the malicious activity
2. Respond with your findings
3. Implement measures to prevent recurrence

**Our Contact:**
[Your Name]
[Your Email]
[Your Phone]

**Reference:** [Case Number]

We appreciate your prompt attention to this matter.
```

**False Positive Response:**
```markdown
**Subject:** Re: False Positive Report - [IP Address]

Dear [Reporter Name],

Thank you for reporting the potential false positive for IP [IP Address].

**Our Investigation:**
- IP: [IP Address]
- Organization: [Org Name]
- Block Reason: [Original reason]
- Current Status: [Under Review/Confirmed False Positive/Still Valid]

**Action Taken:**
- [x] Block removed
- [x] Added to allowlist
- [x] Under further investigation
- [x] Confirmed valid block (with explanation)

**Next Steps:**
[Description of any follow-up actions]

**Contact:** [Support Contact Information]

We appreciate your report and will use this information to improve our systems.
```

### 5c. Escalation Paths

**Internal Escalation:**
1. **Level 1**: Security Operations Team
   - Initial triage and investigation
   - Standard block/allow decisions
   
2. **Level 2**: Security Leadership
   - Major ISP blocks (Tier 1 providers)
   - High-risk blocks (financial, healthcare)
   - Significant false positive incidents
   
3. **Level 3**: Executive Leadership
   - Government or critical infrastructure blocks
   - Legal implications
   - Major customer impact

**External Escalation:**
1. **ISP Abuse Contact**: Initial contact for abuse reports
2. **CERT/CSIRT**: National CERT for critical incidents
3. **Law Enforcement**: For criminal investigations
4. **Legal Counsel**: For legal matters and compliance

## 6. Operational Reporting

### 6a. Weekly Report Template

```markdown
# ISP Blocking Weekly Report

## Period: [Start Date] - [End Date]

### Summary Statistics
- Total Active Blocks: [Number]
- New Blocks Added: [Number]
- Blocks Removed: [Number]
- Total Blocked Connections: [Number]
- False Positive Reports: [Number]
- False Positive Rate: [Percentage]%

### Top Blocked ISPs
| Rank | ISP Name | Blocks | Connections | False Positives |
|------|----------|--------|-------------|------------------|
| 1 | [ISP 1] | [Num] | [Num] | [Num] |
| 2 | [ISP 2] | [Num] | [Num] | [Num] |
| 3 | [ISP 3] | [Num] | [Num] | [Num] |

### New Blocks This Week
| ISP Name | Handle | Score | Reason | Date Added |
|----------|--------|-------|-------|------------|
| [ISP] | [Handle] | [Score] | [Reason] | [Date] |

### Removed Blocks This Week
| ISP Name | Handle | Original Score | Removal Reason | Date Removed |
|----------|--------|---------------|----------------|--------------|
| [ISP] | [Handle] | [Score] | [Reason] | [Date] |

### False Positive Analysis
[Brief analysis of any false positives, root causes, and corrective actions]

### Effectiveness Assessment
[Assessment of overall blocking effectiveness and recommendations for improvement]

### Action Items
- [x] [Action Item 1]
- [x] [Action Item 2]
- [x] [Action Item 3]

### Next Week Focus
[Planned activities for next week]
```

### 6b. Monthly Review Report Template

```markdown
# ISP Blocking Monthly Review

## Month: [Month Year]

### Executive Summary
[Brief summary of month's activities, key metrics, and overall assessment]

### Key Metrics
- Total ISP Blocks: [Number]
- Blocked Connections: [Number]
- False Positive Rate: [Percentage]%
- Average Block Duration: [Days] days
- Most Effective Block: [ISP Name] ([Number] connections blocked)

### Trend Analysis
[Analysis of trends over the month, comparisons to previous months]

### Top Blocked ISPs (By Volume)
[Chart or table showing top ISPs by blocked connections]

### Top Blocked ISPs (By Effectiveness)
[Chart or table showing top ISPs by block rate]

### False Positive Analysis
[Detailed analysis of false positives, root causes, and process improvements]

### Block Lifecycle Analysis
[Analysis of how long blocks remain in place, removal reasons, etc.]

### Threat Intelligence Updates
[Updates from threat intelligence sources, new trends, emerging threats]

### Process Improvements
[Recommendations for improving the blocking process based on month's experience]

### Action Plan
[Specific actions to be taken in the coming month]

### Appendix
- Full list of active blocks
- Detailed metrics breakdown
- Incident reports (if any)
```

## 7. Tools and Automation

### 7a. Required Tools

**Monitoring:**
- Grafana (for dashboards)
- Prometheus (for metrics)
- Loki (for logs)
- Alertmanager (for alerts)

**Threat Intelligence:**
- MISP (for sharing and receiving threat intelligence)
- OpenCTI (for threat intelligence management)
- Abuse.ch feeds
- Spamhaus feeds

**Automation:**
- Ansible (for configuration management)
- Terraform (for infrastructure as code)
- GitHub Actions (for CI/CD)

### 7b. Proposed Automation Scripts

**isp-block-manager.sh:**
```bash
#!/bin/bash
# ISP Block Management Script

function add_isp_block() {
    # Add new ISP block with research documentation
    echo "Adding ISP block for $1"
    # Implementation here
}

function remove_isp_block() {
    # Remove ISP block with proper documentation
    echo "Removing ISP block for $1"
    # Implementation here
}

function review_isp_blocks() {
    # Review all active ISP blocks
    echo "Reviewing active ISP blocks"
    # Implementation here
}

function test_isp_block() {
    # Test ISP block in staging
    echo "Testing ISP block for $1"
    # Implementation here
}

# Main script logic here
```

**isp-monitoring-dashboard.json:**
```json
{
  "title": "ISP Blocking Dashboard",
  "panels": [
    {
      "title": "Active ISP Blocks",
      "type": "stat",
      "targets": [
        {
          "expr": "ja4proxy_isp_blocks_active",
          "legendFormat": "Active Blocks"
        }
      ]
    },
    {
      "title": "Blocks by ISP",
      "type": "table",
      "targets": [
        {
          "expr": "topk(10, ja4proxy_isp_blocks_total)",
          "legendFormat": "{{org}}"
        }
      ]
    }
  ]
}
```

## 8. Training and Documentation

### 8a. Team Training Requirements

**Security Operations Team:**
- ISP blocking procedures
- Research and vetting processes
- Implementation and testing
- Monitoring and troubleshooting
- Communication and escalation

**Security Leadership:**
- Approval processes
- Risk assessment
- Escalation procedures
- Reporting and metrics

**Incident Response Team:**
- False positive handling
- Block removal procedures
- Communication templates
- Escalation paths

### 8b. Documentation Requirements

**Required Documentation:**
- [x] ISP Blocking Policy (this document)
- [x] Research templates
- [x] Implementation checklists
- [x] Monitoring procedures
- [x] Maintenance procedures
- [x] Communication templates
- [x] Escalation paths
- [x] Training materials
- [x] FAQ and troubleshooting guide

**Documentation Maintenance:**
- Review and update quarterly
- Update after significant incidents
- Incorporate lessons learned
- Keep versions in git for audit trail

## 9. Compliance and Audit

### 9a. Audit Requirements

**Internal Audits:**
- Quarterly review of all active blocks
- Annual review of blocking policy
- Documentation audit (semi-annual)

**External Audits:**
- Provide blocking policy to auditors
- Demonstrate research and vetting processes
- Show monitoring and effectiveness metrics
- Document false positive handling

### 9b. Audit Trail Requirements

**Required Audit Logs:**
- Block implementation (who, when, why)
- Block removal (who, when, why)
- Score adjustments (who, when, why)
- False positive reports and resolutions
- Policy changes and approvals

**Audit Log Format:**
```json
{
  "timestamp": "2024-03-20T14:30:00Z",
  "action": "block_added",
  "org_name": "Bad Hosting",
  "org_handle": "BAD-1",
  "score": 45,
  "reason": "Bulletproof hosting with ignored abuse reports",
  "requested_by": "security-analyst",
  "approved_by": "security-lead",
  "approval_date": "2024-03-20",
  "effective_date": "2024-03-21T00:00:00Z",
  "references": [
    "https://spamhaus.org/drop/",
    "https://abuse.ch"
  ]
}
```

## 10. Continuous Improvement

### 10a. Lessons Learned Process

**After Significant Incidents:**
1. Conduct post-incident review
2. Identify root causes
3. Develop corrective actions
4. Update procedures and documentation
5. Implement process improvements
6. Train team on changes

### 10b. Metrics for Improvement

**Key Improvement Metrics:**
- False positive rate (target: <2%)
- Block effectiveness (target: >90%)
- Research to implementation time (target: <48 hours)
- Block removal accuracy (target: 100%)

### 10c. Feedback Loops

**Feedback Sources:**
- False positive reports
- Team debriefs
- Threat intelligence updates
- User feedback
- Audit findings

**Feedback Process:**
1. Collect feedback
2. Analyze trends
3. Identify improvements
4. Implement changes
5. Monitor results
6. Close the loop

## Acceptance Criteria

### Documentation
- [x] ISP Blocking Policy document completed
- [x] Research template created
- [x] Implementation checklists created
- [x] Monitoring procedures documented
- [x] Maintenance procedures documented
- [x] Communication templates created
- [x] Escalation paths documented
- [x] Training materials created
- [x] FAQ and troubleshooting guide created

### Process Implementation
- [x] Research and vetting process established
- [x] Implementation workflow tested
- [x] Monitoring dashboard created
- [x] Alerting rules configured
- [x] Maintenance procedures tested
- [x] Communication templates tested
- [x] Escalation paths tested

### Training
- [x] Security operations team trained
- [x] Security leadership trained
- [x] Incident response team trained
- [x] Training materials available

### Tools
- [x] Monitoring dashboard deployed
- [x] Alerting rules deployed
- [x] Automation scripts created
- [x] Documentation repository established

### Compliance
- [x] Audit trail established
- [x] Audit procedures documented
- [x] Compliance documentation completed

## Metrics for Success

**Operational Metrics:**
- Time to implement new blocks: <48 hours
- False positive rate: <2%
- Block effectiveness: >90%
- Team training completion: 100%

**Process Metrics:**
- Documentation completeness: 100%
- Process adherence: >95%
- Incident response time: <1 hour
- Customer satisfaction: >90%

**Security Metrics:**
- Reduction in malicious traffic: >30%
- Increase in blocked attacks: >20%
- Reduction in successful attacks: >15%
- Improvement in detection rate: >10%

## Timeline

**Phase Duration:** 4-6 weeks

**Week 1-2:** Documentation and Policy Development
- Create ISP Blocking Policy document
- Develop research and vetting procedures
- Create implementation workflows
- Develop monitoring procedures

**Week 3:** Tooling and Automation
- Create monitoring dashboard
- Configure alerting rules
- Develop automation scripts
- Set up documentation repository

**Week 4:** Training and Testing
- Train security operations team
- Train security leadership
- Train incident response team
- Test procedures in staging

**Week 5:** Deployment and Review
- Deploy to production
- Monitor initial implementation
- Gather feedback
- Make adjustments

**Week 6:** Finalization
- Complete documentation
- Finalize procedures
- Conduct audit
- Close phase

## Dependencies

**Phase Dependencies:**
- Phase 11 (RDAP Enrichment) - Must be complete
- Phase 14 (Production Hardening) - Should be complete
- Phase 19 (Backup/Restore) - Should be complete

**Tool Dependencies:**
- Grafana/Prometheus/Loki - For monitoring
- MISP/OpenCTI - For threat intelligence
- Ansible/Terraform - For automation

## Risks and Mitigation

**Risk: False positives causing legitimate traffic blocks**
- Mitigation: Conservative scoring, thorough vetting, monitoring

**Risk: Over-blocking causing customer impact**
- Mitigation: Gradual implementation, monitoring, quick rollback

**Risk: Under-blocking missing malicious traffic**
- Mitigation: Regular reviews, threat intelligence updates

**Risk: Process not followed consistently**
- Mitigation: Training, checklists, automation, audits

**Risk: Documentation not maintained**
- Mitigation: Regular reviews, version control, ownership

## Appendix

### A. Glossary

**ISP**: Internet Service Provider
**ASN**: Autonomous System Number
**RDAP**: Registration Data Access Protocol
**C2**: Command and Control
**TI**: Threat Intelligence
**SOC**: Security Operations Center
**CERT**: Computer Emergency Response Team
**CSIRT**: Computer Security Incident Response Team

### B. References

1. Spamhaus ASN-DROP List
2. Abuse.ch Threat Intelligence
3. RIPE NCC Abuse Contact Database
4. ARIN Abuse Contact Database
5. MISP Threat Sharing Standard
6. OpenCTI Threat Intelligence Platform
7. NIST SP 800-61 Incident Handling Guide

### C. Related Documents

- Phase 11: RDAP Enrichment & Block Expansion
- INCIDENT_RESPONSE.md
- DEPLOYMENT_SECURITY_MODEL.md
- OPERATIONS.md

---
- name: Verify ServiceNow enabled
  hosts: ja4proxy-rocky9
  become: true
  gather_facts: false

  tasks:
    - name: Read stub ServiceNow request log
      ansible.builtin.slurp:
        src: /tmp/servicenow-stub/requests.log
      register: sn_log

    - name: Decode request log
      ansible.builtin.set_fact:
        sn_requests: "{{ sn_log.content | b64decode | splitlines }}"

    - name: Assert at least one POST was recorded
      ansible.builtin.assert:
        that:
          - sn_requests | length >= 1
          - "'POST' in sn_requests[0]"
        fail_msg: "ServiceNow stub received no POST requests — CMDB registration did not run"

    - name: Assert POST contains JA4proxy identifiers
      ansible.builtin.assert:
        that:
          - "'JA4PROXY-' in sn_requests[0]"
          - "'JA4proxy TLS Security Proxy' in sn_requests[0]"
        fail_msg: "ServiceNow POST did not contain expected JA4proxy identifiers"

    - name: Display recorded ServiceNow requests
      ansible.builtin.debug:
        msg: "ServiceNow stub recorded {{ sn_requests | length }} POST(s)"

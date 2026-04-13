---
- name: Verify ServiceNow disabled
  hosts: ja4proxy-rocky9
  become: true
  gather_facts: false

  tasks:
    - name: Confirm servicenow_enabled default is false
      ansible.builtin.debug:
        msg: "ServiceNow CMDB registration was skipped (servicenow_enabled=false)"

    - name: Verify no ServiceNow artifacts in role files
      ansible.builtin.command:
        cmd: "grep -rl 'servicenow.itsm' /etc/ || true"
      register: grep_result
      changed_when: false

    - name: Assert no ServiceNow tasks executed
      ansible.builtin.assert:
        that:
          - grep_result.stdout | length == 0
        fail_msg: "ServiceNow tasks should not run when servicenow_enabled is false"

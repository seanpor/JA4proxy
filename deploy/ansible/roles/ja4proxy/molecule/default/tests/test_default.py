---
- name: Verify default scenario
  hosts: ja4proxy-rocky9
  become: true
  gather_facts: false

  tasks:
    - name: Check systemd unit file exists
      ansible.builtin.stat:
        path: "/etc/systemd/system/ja4proxy.service"
      register: unit_stat

    - name: Assert unit file was created
      ansible.builtin.assert:
        that:
          - unit_stat.stat.exists
        fail_msg: "systemd unit file was not deployed"

    - name: Check configuration file exists
      ansible.builtin.stat:
        path: "/etc/ja4proxy/proxy.yml"
      register: config_stat

    - name: Assert config file was created
      ansible.builtin.assert:
        that:
          - config_stat.stat.exists
        fail_msg: "Configuration file was not deployed"

    - name: Verify no proxy.py references in role files
      ansible.builtin.command:
        cmd: "grep -r 'proxy\\.py' /etc/systemd/system/ja4proxy.service /etc/ja4proxy/ || true"
      register: grep_result
      changed_when: false

    - name: Assert no proxy.py references found
      ansible.builtin.assert:
        that:
          - grep_result.stdout | length == 0
        fail_msg: "Found proxy.py reference in deployed files — role must only deploy Go binary"

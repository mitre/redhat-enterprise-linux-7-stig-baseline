# encoding: UTF-8

control 'SV-204628' do
  title "The Red Hat Enterprise Linux operating system access control program
must be configured to grant or deny system access to specific hosts and
services."
  desc  "If the systems access control program is not configured with
appropriate rules for allowing and denying access to system network resources,
services may be accessible to unauthorized hosts."
  desc  'rationale', ''
  desc  'check', "
    If the \"firewalld\" package is not installed, ask the System Administrator
(SA) if another firewall application (such as iptables) is installed. If an
application firewall is not installed, this is a finding.

    Verify the system's access control program is configured to grant or deny
system access to specific hosts.

    Check to see if \"firewalld\" is active with the following command:

    # systemctl status firewalld
    firewalld.service - firewalld - dynamic firewall daemon
    Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
    Active: active (running) since Sun 2014-04-20 14:06:46 BST; 30s ago

    If \"firewalld\" is active, check to see if it is configured to grant or
deny access to specific hosts or services with the following commands:

    # firewall-cmd --get-default-zone
    public

    # firewall-cmd --list-all --zone=public
    public (active)
    target: default
    icmp-block-inversion: no
    interfaces: eth0
    sources:
    services: mdns ssh
    ports:
    protocols:
    masquerade: no
    forward-ports:
    icmp-blocks:

    If \"firewalld\" is not active, determine whether \"tcpwrappers\" is being
used by checking whether the \"hosts.allow\" and \"hosts.deny\" files are empty
with the following commands:

    # ls -al /etc/hosts.allow
    rw-r----- 1 root root 9 Aug 2 23:13 /etc/hosts.allow

    # ls -al /etc/hosts.deny
    -rw-r----- 1 root root 9 Apr 9 2007 /etc/hosts.deny

    If \"firewalld\" and \"tcpwrappers\" are not installed, configured, and
active, ask the SA if another access control program (such as iptables) is
installed and active. Ask the SA to show that the running configuration grants
or denies access to specific hosts or services.

    If \"firewalld\" is active and is not configured to grant access to
specific hosts or \"tcpwrappers\" is not configured to grant or deny access to
specific hosts, this is a finding.
  "
  desc  'fix', "
    If \"firewalld\" is installed and active on the system, configure rules for
allowing specific services and hosts.

    If \"firewalld\" is not \"active\", enable \"tcpwrappers\" by configuring
\"/etc/hosts.allow\" and \"/etc/hosts.deny\" to allow or deny access to
specific hosts.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204628'
  tag rid: 'SV-204628r603261_rule'
  tag stig_id: 'RHEL-07-040810'
  tag fix_id: 'F-4752r89077_fix'
  tag cci: ['CCI-000366']
  tag legacy: ['SV-86939', 'V-72315']
  tag nist: ['CM-6 b']
end


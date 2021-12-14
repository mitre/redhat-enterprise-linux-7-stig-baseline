# encoding: UTF-8

control 'SV-204524' do
  title "The Red Hat Enterprise Linux operating system must audit all uses of
the setxattr syscall."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    When a user logs on, the auid is set to the uid of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
-1. The auid representation is an unsigned 32-bit integer, which equals
4294967295. The audit system interprets -1, 4294967295, and \"unset\" in the
same way.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"setxattr\" syscall occur.

    Check the file system rules in \"/etc/audit/audit.rules\" with the
following commands:

    # grep -iw setxattr /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -k
perm_mod

    -a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -k
perm_mod

    If both the \"b32\" and \"b64\" audit rules are not defined for the
\"setxattr\" syscall, this is a finding.
  "
  desc  'fix', "
    Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"setxattr\" syscall occur.

    Add or update the following rules in \"/etc/audit/rules.d/audit.rules\":

    -a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -k
perm_mod

    -a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -k
perm_mod

    The audit daemon must be restarted for the changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000458-GPOS-00203'
  tag satisfies: ['SRG-OS-000458-GPOS-00203', 'SRG-OS-000392-GPOS-00172',
'SRG-OS-000064-GPOS-00033']
  tag gid: 'V-204524'
  tag rid: 'SV-204524r603261_rule'
  tag stig_id: 'RHEL-07-030440'
  tag fix_id: 'F-4648r462732_fix'
  tag cci: ['CCI-000172']
  tag legacy: ['SV-86735', 'V-72111']
  tag nist: ['AU-12 c']
end


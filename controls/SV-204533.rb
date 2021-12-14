# encoding: UTF-8

control 'SV-204533' do
  title "The Red Hat Enterprise Linux operating system must audit all uses of
the open_by_handle_at syscall."
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
successful/unsuccessful attempts to use the \"open_by_handle_at\" syscall occur.

    Check the file system rules in \"/etc/audit/audit.rules\" with the
following commands:

    # grep -iw open_by_handle_at /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F
auid>=1000 -F auid!=unset -k access

    -a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F
auid>=1000 -F auid!=unset -k access

    -a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F
auid>=1000 -F auid!=unset -k access

    -a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F
auid>=1000 -F auid!=unset -k access

    If both the \"b32\" and \"b64\" audit rules are not defined for the
\"open_by_handle_at\" syscall, this is a finding.

    If the output does not produce rules containing \"-F exit=-EPERM\", this is
a finding.

    If the output does not produce rules containing \"-F exit=-EACCES\", this
is a finding.
  "
  desc  'fix', "
    Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"open_by_handle_at\" syscall occur.

    Add or update the following rules in \"/etc/audit/rules.d/audit.rules\":

    -a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F
auid>=1000 -F auid!=unset -k access

    -a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F
auid>=1000 -F auid!=unset -k access

    -a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F
auid>=1000 -F auid!=unset -k access

    -a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F
auid>=1000 -F auid!=unset -k access

    The audit daemon must be restarted for the changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000458-GPOS-00203',
'SRG-OS-000461-GPOS-00205', 'SRG-OS-000392-GPOS-00172']
  tag gid: 'V-204533'
  tag rid: 'SV-204533r603261_rule'
  tag stig_id: 'RHEL-07-030530'
  tag fix_id: 'F-4657r462604_fix'
  tag cci: ['CCI-000172', 'CCI-002884']
  tag legacy: ['SV-86753', 'V-72129']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']
end


# encoding: UTF-8

control 'SV-204560' do
  title "The Red Hat Enterprise Linux operating system must audit all uses of
the init_module syscall."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"init_module\" syscall occur.

    Check the auditing rules in \"/etc/audit/audit.rules\" with the following
command:

    # grep -iw init_module /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S init_module -k module-change

    -a always,exit -F arch=b64 -S init_module -k module-change

    If both the \"b32\" and \"b64\" audit rules are not defined for the
\"init_module\" syscall, this is a finding.
  "
  desc  'fix', "
    Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"init_module\" syscall occur.

    Add or update the following rules in \"/etc/audit/rules.d/audit.rules\":

    -a always,exit -F arch=b32 -S init_module -k module-change

    -a always,exit -F arch=b64 -S init_module -k module-change

    The audit daemon must be restarted for the changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag satisfies: ['SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag gid: 'V-204560'
  tag rid: 'SV-204560r603261_rule'
  tag stig_id: 'RHEL-07-030820'
  tag fix_id: 'F-4684r88873_fix'
  tag cci: ['CCI-000172']
  tag legacy: ['V-72187', 'SV-86811']
  tag nist: ['AU-12 c']
end


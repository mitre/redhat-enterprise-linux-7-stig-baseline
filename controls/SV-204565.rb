# encoding: UTF-8

control 'SV-204565' do
  title "The Red Hat Enterprise Linux operating system must generate audit
records for all account creations, modifications, disabling, and termination
events that affect /etc/group."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system must generate audit records for all account
creations, modifications, disabling, and termination events that affect
\"/etc/group\".

    Check the auditing rules in \"/etc/audit/audit.rules\" with the following
command:

    # grep /etc/group /etc/audit/audit.rules

    -w /etc/group -p wa -k identity

    If the command does not return a line, or the line is commented out, this
is a finding.
  "
  desc  'fix', "
    Configure the operating system to generate audit records for all account
creations, modifications, disabling, and termination events that affect
\"/etc/group\".

    Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

    -w /etc/group -p wa -k identity

    The audit daemon must be restarted for the changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag gid: 'V-204565'
  tag rid: 'SV-204565r603261_rule'
  tag stig_id: 'RHEL-07-030871'
  tag fix_id: 'F-4689r88888_fix'
  tag cci: ['CCI-000018', 'CCI-000172', 'CCI-001403', 'CCI-002130']
  tag legacy: ['SV-87817', 'V-73165']
  tag nist: ['AC-2 (4)', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)']
end


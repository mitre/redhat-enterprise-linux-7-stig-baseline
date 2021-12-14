# encoding: UTF-8

control 'SV-204540' do
  title "The Red Hat Enterprise Linux operating system must generate audit
records for all unsuccessful account access events."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system generates audit records when unsuccessful
account access events occur.

    Check the file system rule in \"/etc/audit/audit.rules\" with the following
commands:

    # grep -i /var/run/faillock /etc/audit/audit.rules

    -w /var/run/faillock -p wa -k logins

    If the command does not return any output, this is a finding.
  "
  desc  'fix', "
    Configure the operating system to generate audit records when unsuccessful
account access events occur.

    Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

    -w /var/run/faillock -p wa -k logins

    The audit daemon must be restarted for the changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000470-GPOS-00214',
'SRG-OS-000473-GPOS-00218']
  tag gid: 'V-204540'
  tag rid: 'SV-204540r603261_rule'
  tag stig_id: 'RHEL-07-030610'
  tag fix_id: 'F-4664r88813_fix'
  tag cci: ['CCI-000126', 'CCI-000172', 'CCI-002884']
  tag legacy: ['V-72145', 'SV-86769']
  tag nist: ['AU-2 d', 'AU-12 c', 'MA-4 (1) (a)']
end


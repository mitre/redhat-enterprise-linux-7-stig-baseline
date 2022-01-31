control 'V-72137' do
  title "The Red Hat Enterprise Linux operating system must audit all uses of
the setsebool command."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).


  "
  tag 'rationale': ''
  tag 'check': "
    Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"setsebool\" command occur.

    Check the file system rule in \"/etc/audit/audit.rules\" with the following
command:

    # grep -i /usr/sbin/setsebool /etc/audit/audit.rules

    -a always,exit -F path=/usr/sbin/setsebool -F auid>=1000 -F
auid!=4294967295 -k privileged-priv_change

    If the command does not return any output, this is a finding.
  "
  tag 'fix': "
    Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"setsebool\" command occur.

    Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

    -a always,exit -F path=/usr/sbin/setsebool -F auid>=1000 -F
auid!=4294967295 -k privileged-priv_change

    The audit daemon must be restarted for the changes to take effect.
  "
  tag severity: nil
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000463-GPOS-00207',
                  'SRG-OS-000465-GPOS-00209']
  tag gid: 'V-72137'
  tag rid: 'SV-86761r4_rule'
  tag stig_id: 'RHEL-07-030570'
  tag fix_id: 'F-78489r6_fix'
  tag cci: ['CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 c', 'MA-4 (1) (a)']

  audit_file = '/usr/sbin/setsebool'

  if file(audit_file).exist?
    impact 0.5
  else
    impact 0.0
  end

  if file(audit_file).exist?
    describe auditd.file(audit_file) do
      its('permissions') { should include ['x'] }
      its('action') { should_not include 'never' }
    end
  end

  unless file(audit_file).exist?
    describe "The #{audit_file} file does not exist" do
      skip "The #{audit_file} file does not exist, this requirement is Not Applicable."
    end
  end
end

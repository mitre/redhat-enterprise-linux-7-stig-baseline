control 'V-72101' do
  title "The Red Hat Enterprise Linux operating system must audit all uses of
the lchown syscall."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).


  "
  tag  'rationale': ''
  tag  'check': "
    Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"lchown\" syscall occur.

    Check the file system rules in \"/etc/audit/audit.rules\" with the
following commands:

    # grep -iw lchown /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k
perm_mod

    -a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k
perm_mod

    If both the \"b32\" and \"b64\" audit rules are not defined for the
\"lchown\" syscall, this is a finding.
  "
  desc  'fix', "
    Add or update the following rules in \"/etc/audit/rules.d/audit.rules\":

    -a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k
perm_mod

    -a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k
perm_mod

    The audit daemon must be restarted for the changes to take effect.
  "
  impact 0.5
  tag severity: nil
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000392-GPOS-00172',
                  'SRG-OS-000458-GPOS-00203', 'SRG-OS-000474-GPOS-00219']
  tag gid: 'V-72101'
  tag rid: 'SV-86725r5_rule'
  tag stig_id: 'RHEL-07-030390'
  tag fix_id: 'F-78453r8_fix'
  tag cci: ['CCI-000126', 'CCI-000172']
  tag nist: ['AU-2 d', 'AU-12 c']

  describe auditd.syscall('lchown').where { arch == 'b32' } do
    its('action.uniq') { should eq ['always'] }
    its('list.uniq') { should eq ['exit'] }
  end
  if os.arch == 'x86_64'
    describe auditd.syscall('lchown').where { arch == 'b64' } do
      its('action.uniq') { should eq ['always'] }
      its('list.uniq') { should eq ['exit'] }
    end
  end
end

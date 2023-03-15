control 'SV-250314' do
  title 'The Red Hat Enterprise Linux operating system must elevate the SELinux context when an administrator calls the sudo command.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Note: Per OPORD 16-0080, the preferred endpoint security tool is Endpoint Security for Linux (ENSL) in conjunction with SELinux.

Verify the operating system elevates the SELinux context when an administrator calls the sudo command with the following command:

This command must be ran as root:
# grep sysadm_r /etc/sudoers /etc/sudoers.d/*
%wheel ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL

If results are returned from more than one file location, this is a finding.

If a designated sudoers administrator group or account(s) is not configured to elevate the SELinux type and role to "sysadm_t" and "sysadm_r" with the use of the sudo command, this is a finding.'
  desc 'fix', 'Configure the operating system to elevate the SELinux context when an administrator calls the sudo command.
Edit a file in the /etc/sudoers.d directory with the following command:
$ sudo visudo -f /etc/sudoers.d/<customfile>

Use the following example to build the <customfile> in the /etc/sudoers.d directory to allow any administrator belonging to a designated sudoers admin group to elevate their SELinux context with the use of the sudo command:
%wheel ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag gid: 'V-250314'
  tag rid: 'SV-250314r809217_rule'
  tag stig_id: 'RHEL-07-020023'
  tag fix_id: 'F-53702r792848_fix'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag legacy: []
  tag subsystems: ['selinux']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container -- kernel config' do
      skip 'Control not applicable within a container -- kernel config'
    end
  else
    describe command('grep sysadm_r /etc/sudoers /etc/sudoers.d/*').stdout.strip do
      it { should match /TYPE=sysadm_t\s+ROLE=sysadm_r/ }
      it { should_not match /\n/ }
    end
  end
end
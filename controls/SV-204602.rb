control 'SV-204602' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow
    compression or only allows compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression
    software could result in compromise of the system from an unauthenticated connection, potentially with root
    privileges.'
  desc 'check', 'Note: For RHEL 7.4 and above, this requirement is not applicable.

Verify the SSH daemon performs compression after a user successfully authenticates.

Check that the SSH daemon performs compression after a user successfully authenticates with the following command:

     # grep -i compression /etc/ssh/sshd_config
     Compression delayed

If the "Compression" keyword is set to "yes", is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Uncomment the "Compression" keyword in "/etc/ssh/sshd_config" (this file may be named differently or
    be in a different location if using a version of SSH that is provided by a third-party vendor) on the system and set
    the value to "delayed" or "no":
    Compression no
    The SSH service must be restarted for changes to take effect.'
  impact 0.5
  tag legacy: ['SV-86891', 'V-72267']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204602'
  tag rid: 'SV-204602r880758_rule'
  tag stig_id: 'RHEL-07-040470'
  tag fix_id: 'F-4726r880757_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['ssh']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end

  elsif os.release.to_f >= 2.0
    impact 0.0
    describe "The release is #{os.release}" do
      # skip 'For RHEL 7.4 and above, this requirement is not applicable.'
      skip 'For Amazon Linux 2, openssh.x86_64:7.4p1-22.amzn2.0.3 is installed. OpenSSH 7.4p1 or later has disabled compression by default and only allows compression after successful authentication. Hence this check is not applicable.'
    end

  else

    describe.one do
      describe sshd_config do
        its('Compression') { should cmp 'delayed' }
      end
      describe sshd_config do
        its('Compression') { should cmp 'no' }
      end
    end
  end
end

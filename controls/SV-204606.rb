control 'SV-204606' do
  title 'The Red Hat Enterprise Linux operating system must not contain .shosts files.'
  desc 'The .shosts files are used to configure host-based authentication for individual users or the system via
    SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not
    require interactive identification and authentication of a connection request, or for the use of two-factor
    authentication.'
  desc 'check', %q(Verify there are no ".shosts" files on the system.
    Check the system for the existence of these files with the following command:
    # find / -name '*.shosts'
    If any ".shosts" files are found on the system, this is a finding.)
  desc 'fix', 'Remove any found ".shosts" files from the system.
    # rm /[path]/[to]/[file]/.shosts'
  impact 0.7
  tag legacy: ['SV-86901', 'V-72277']
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204606'
  tag rid: 'SV-204606r603261_rule'
  tag stig_id: 'RHEL-07-040540'
  tag fix_id: 'F-4730r89011_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['ssh']
  tag 'host'
  tag 'container'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  else
    describe command("find / -xdev -xautofs -name '*.shosts'") do
      its('stdout.strip') { should be_empty }
    end
  end
end

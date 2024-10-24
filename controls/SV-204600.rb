control 'SV-204600' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon performs strict
    mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log on to
    the system as another user.'
  desc 'check', 'Verify the SSH daemon performs strict mode checking of home directory configuration files.
    The location of the "sshd_config" file may vary if a different daemon is in use.
    Inspect the "sshd_config" file with the following command:
    # grep -i strictmodes /etc/ssh/sshd_config
    StrictModes yes
    If "StrictModes" is set to "no", is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Uncomment the "StrictModes" keyword in "/etc/ssh/sshd_config" (this file may be named differently or
    be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to
    "yes":
    StrictModes yes
    The SSH service must be restarted for changes to take effect.'
  impact 0.5
  tag legacy: ['SV-86887', 'V-72263']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204600'
  tag rid: 'SV-204600r603261_rule'
  tag stig_id: 'RHEL-07-040450'
  tag fix_id: 'F-4724r88993_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['ssh']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  else
    describe sshd_config do
      its('StrictModes') { should cmp 'yes' }
    end
  end
end

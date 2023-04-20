control 'SV-204597' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the SSH private host key files have mode 0640 or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  desc 'check', %q(Verify the SSH private host key files have mode "0640" or less permissive.

The following command will find all SSH private key files on the system and list their modes:

     # find / -name '*ssh_host*key' | xargs ls -lL

     -rw-r----- 1 root ssh_keys 112 Apr 1 11:59 ssh_host_dsa_key
     -rw-r----- 1 root ssh_keys 202 Apr 1 11:59 ssh_host_key
     -rw-r----- 1 root ssh_keys 352 Apr 1 11:59 ssh_host_rsa_key

If any file has a mode more permissive than "0640", this is a finding.)
  desc 'fix', 'Configure the mode of SSH private host key files under "/etc/ssh" to "0640" with the following command:

# chmod 0640 /path/to/file/ssh_host*key'
  impact 0.5
  tag legacy: ['V-72257', 'SV-86881']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204597'
  tag rid: 'SV-204597r880743_rule'
  tag stig_id: 'RHEL-07-040420'
  tag fix_id: 'F-4721r880742_fix'
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
    pub_files = command("find #{input('private_host_key_directories').join(' ')} -xdev -name '*ssh_host*key'").stdout.split("\n")
    if !pub_files.nil? and !pub_files.empty?
      pub_files.each do |pubfile|
        describe file(pubfile) do
          it { should_not be_more_permissive_than(input('private_host_key_file_mode')) }
        end
      end
    else
      describe 'No public host key files found.' do
        subject { pub_files.nil? or pub_files.empty? }
        it { should eq true }
      end
    end
  end
end

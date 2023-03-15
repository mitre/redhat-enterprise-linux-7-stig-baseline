control 'SV-204472' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all files and directories
    contained in local interactive user home directories are group-owned by a group of which the home directory owner is
    a member.'
  desc "If a local interactive user's files are group-owned by a group of which the user is not a member, unintended
    users may be able to access them."
  desc 'check', %q(Verify all files and directories in a local interactive user home directory are group-owned by a
    group the user is a member of.
    Check the group owner of all files and directories in a local interactive user's home directory with the following
    command:
    Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".
    # ls -lLR /<home directory>/<users home directory>/
    -rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
    -rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
    -rw-r--r-- 1 smithj sa        231 Mar  5 17:06 file3
    If any files are found with an owner different than the group home directory user, check to see if the user is a
    member of that group with the following command:
    # grep smithj /etc/group
    sa:x:100:juan,shelley,bob,smithj
    smithj:x:521:smithj
    If the user is not a member of a group that group owns file(s) in a local interactive user's home directory, this is
    a finding.)
  desc 'fix', %q(Change the group of a local interactive user's files and directories to a group that the interactive
    user is a member of. To change the group owner of a local interactive user's files and directories, use the
    following command:
    Note: The example will be for the user smithj, who has a home directory of "/home/smithj" and is a member of the
    users group.
    # chgrp users /home/smithj/<file>)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag legacy: ['V-72025', 'SV-86649']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204472'
  tag rid: 'SV-204472r603261_rule'
  tag stig_id: 'RHEL-07-020670'
  tag fix_id: 'F-4596r88609_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['home_dirs']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else

    exempt_home_users = input('exempt_home_users')
    non_interactive_shells = input('non_interactive_shells')

    ignore_shells = non_interactive_shells.join('|')

    uid_min = login_defs.read_params['UID_MIN'].to_i
    uid_min = 1000 if uid_min.nil?

    findings = Set[]
    users.where do
      !shell.match(ignore_shells) && (uid >= uid_min || uid == 0)
    end.entries.each do |user_info|
      next if exempt_home_users.include?(user_info.username.to_s)

      find_args = ''
      user_info.groups.each do |curr_group|
        # some key files and secure dirs (like .ssh) are group owned 'root'
        find_args += "-not -group #{curr_group} -o root"
      end
      findings += command("find #{user_info.home} -xdev -xautofs #{find_args}").stdout.split("\n")
    end
    describe "Home directory files with incorrect group ownership or not 'root' owned" do
      subject { findings.to_a }
      it { should be_empty }
    end
  end
end

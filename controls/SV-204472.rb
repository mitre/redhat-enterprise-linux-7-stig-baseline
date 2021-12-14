# encoding: UTF-8

control 'SV-204472' do
  title "The Red Hat Enterprise Linux operating system must be configured so
that all files and directories contained in local interactive user home
directories are group-owned by a group of which the home directory owner is a
member."
  desc  "If a local interactive user's files are group-owned by a group of
which the user is not a member, unintended users may be able to access them."
  desc  'rationale', ''
  desc  'check', "
    Verify all files and directories in a local interactive user home directory
are group-owned by a group the user is a member of.

    Check the group owner of all files and directories in a local interactive
user's home directory with the following command:

    Note: The example will be for the user \"smithj\", who has a home directory
of \"/home/smithj\".

    # ls -lLR /<home directory>/<users home directory>/
    -rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
    -rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
    -rw-r--r-- 1 smithj sa        231 Mar  5 17:06 file3

    If any files are found with an owner different than the group home
directory user, check to see if the user is a member of that group with the
following command:

    # grep smithj /etc/group
    sa:x:100:juan,shelley,bob,smithj
    smithj:x:521:smithj

    If the user is not a member of a group that group owns file(s) in a local
interactive user's home directory, this is a finding.
  "
  desc  'fix', "
    Change the group of a local interactive user's files and directories to a
group that the interactive user is a member of. To change the group owner of a
local interactive user's files and directories, use the following command:

    Note: The example will be for the user smithj, who has a home directory of
\"/home/smithj\" and is a member of the users group.

    # chgrp users /home/smithj/<file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204472'
  tag rid: 'SV-204472r603261_rule'
  tag stig_id: 'RHEL-07-020670'
  tag fix_id: 'F-4596r88609_fix'
  tag cci: ['CCI-000366']
  tag legacy: ['V-72025', 'SV-86649']
  tag nist: ['CM-6 b']
end


# encoding: UTF-8

control 'SV-204470' do
  title "The Red Hat Enterprise Linux operating system must be configured so
that all local interactive user home directories are group-owned by the home
directory owners primary group."
  desc  "If the Group Identifier (GID) of a local interactive user's home
directory is not the same as the primary GID of the user, this would allow
unauthorized access to the user's files, and users that share the same group
may not be able to access files that they legitimately should."
  desc  'rationale', ''
  desc  'check', "
    Verify the assigned home directory of all local interactive users is
group-owned by that user's primary GID.

    Check the home directory assignment for all local interactive users on the
system with the following command:

    # ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)

    -rwxr-x--- 1 smithj users 18 Mar 5 17:06 /home/smithj

    Check the user's primary group with the following command:

    # grep $(grep smithj /etc/passwd | awk -F: ‘{print $4}’) /etc/group

    users:x:250:smithj,jonesj,jacksons

    If the user home directory referenced in \"/etc/passwd\" is not group-owned
by that user's primary GID, this is a finding.
  "
  desc  'fix', "
    Change the group owner of a local interactive user's home directory to the
group found in \"/etc/passwd\". To change the group owner of a local
interactive user's home directory, use the following command:

    Note: The example will be for the user \"smithj\", who has a home directory
of \"/home/smithj\", and has a primary group of users.

    # chgrp users /home/smithj
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204470'
  tag rid: 'SV-204470r744102_rule'
  tag stig_id: 'RHEL-07-020650'
  tag fix_id: 'F-4594r88603_fix'
  tag cci: ['CCI-000366']
  tag legacy: ['SV-86645', 'V-72021']
  tag nist: ['CM-6 b']
end


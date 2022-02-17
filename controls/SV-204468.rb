# encoding: UTF-8

control 'SV-204468' do
  title "The Red Hat Enterprise Linux operating system must be configured so
that all local interactive user home directories have mode 0750 or less
permissive."
  desc  "Excessive permissions on local interactive user home directories may
allow unauthorized access to user files by other users."
  desc  'rationale', ''
  desc  'check', "
    Verify the assigned home directory of all local interactive users has a
mode of \"0750\" or less permissive.

    Check the home directory assignment for all non-privileged users on the
system with the following command:

    Note: This may miss interactive users that have been assigned a privileged
User Identifier (UID). Evidence of interactive use may be obtained from a
number of log files containing system logon information.

    # ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
    -rwxr-x--- 1 smithj users  18 Mar  5 17:06 /home/smithj

    If home directories referenced in \"/etc/passwd\" do not have a mode of
\"0750\" or less permissive, this is a finding.
  "
  desc  'fix', "
    Change the mode of interactive user's home directories to \"0750\". To
change the mode of a local interactive user's home directory, use the following
command:

    Note: The example will be for the user \"smithj\".

    # chmod 0750 /home/smithj
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204468'
  tag rid: 'SV-204468r603828_rule'
  tag stig_id: 'RHEL-07-020630'
  tag fix_id: 'F-4592r88597_fix'
  tag cci: ['CCI-000366']
  tag legacy: ['SV-86641', 'V-72017']
  tag nist: ['CM-6 b']
end


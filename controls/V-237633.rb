control 'V-237633' do
  title 'The Red Hat Enterprise Linux operating system must restrict privilege elevation to authorized personnel.'
  desc 'The sudo command allows a user to execute programs with elevated (administrator) privileges. It prompts the
    user for their password and confirms your request to execute a command by checking a file, called sudoers. If the
    "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the
    target system.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'satisfies': nil
  tag 'gid': 'V-237633'
  tag 'rid': 'SV-237633r646850_rule'
  tag 'stig_id': 'RHEL-07-010341'
  tag 'fix_id': 'F-40815r646849_fix'
  tag 'cci': ['CCI-000366']
  tag 'false_negatives': nil
  tag 'false_positives': nil
  tag 'documentable': false
  tag 'mitigations': nil
  tag 'severity_override_guidance': nil
  tag 'potential_impacts': nil
  tag 'third_party_tools': nil
  tag 'mitigation_controls': nil
  tag 'responsibility': nil
  tag 'ia_controls': nil
  tag 'check': 'Verify the "sudoers" file restricts sudo access to authorized personnel.
    $ sudo grep -iw "ALL" /etc/sudoers /etc/sudoers.d/*
    If the either of the following entries are returned, this is a finding:
    ALL     ALL=(ALL) ALL
    ALL     ALL=(ALL:ALL) ALL'
  tag 'fix': 'Remove the following entries from the sudoers file:
    ALL     ALL=(ALL) ALL
    ALL     ALL=(ALL:ALL) ALL'

  describe command('grep -iw "ALL" /etc/sudoers /etc/sudoers.d/*') do
    its('stdout') { should_not match /^ALL\s*ALL=\(ALL\) ALL$/}
    its('stdout') { should_not match /^ALL\s*ALL=\(ALL:ALL\) ALL$/}
  end
end

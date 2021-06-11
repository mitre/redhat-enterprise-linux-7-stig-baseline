control 'V-237634' do
  title 'The Red Hat Enterprise Linux operating system must use the invoking user\'s password for privilege
    escalation when using "sudo".'
  desc 'The sudoers security policy requires that users authenticate themselves before they can use sudo. When
    sudoers requires authentication, it validates the invoking user\'s credentials. If the rootpw, targetpw, or runaspw
    flags are defined and not disabled, by default the operating system will prompt the invoking user for the "root"
    user password.
    For more information on each of the listed configurations, reference the sudoers(5) manual page.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'satisfies': nil
  tag 'gid': 'V-237634'
  tag 'rid': 'SV-237634r646853_rule'
  tag 'stig_id': 'RHEL-07-010342'
  tag 'fix_id': 'F-40816r646852_fix'
  tag 'cci': ['CCI-002227']
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
  tag 'check': 'Verify that the sudoers security policy is configured to use the invoking user\'s password for
    privilege escalation.
    $ sudo egrep -i \'(!rootpw|!targetpw|!runaspw)\' /etc/sudoers /etc/sudoers.d/* | grep -v \'#\'
    /etc/sudoers:Defaults !targetpw
    /etc/sudoers:Defaults !rootpw
    /etc/sudoers:Defaults !runaspw
    If no results are returned, this is a finding
    If "Defaults !targetpw" is not defined, this is a finding.
    If "Defaults !rootpw" is not defined, this is a finding.
    If "Defaults !runaspw" is not defined, this is a finding.'
  tag 'fix': 'Define the following in the Defaults section of the /etc/sudoers file or a configuration file in the
    /etc/sudoers.d/ directory:
    Defaults !targetpw
    Defaults !rootpw
    Defaults !runaspw'
  
  describe command('egrep -i \'(!rootpw|!targetpw|!runaspw)\' /etc/sudoers /etc/sudoers.d/* | grep -v \'#\'') do
    its('stdout') {should_not match /#/}
    its('stdout') {should_not eq nil}
  end
end

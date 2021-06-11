control 'V-237635' do
  title 'The Red Hat Enterprise Linux operating system must require re-authentication when using the "sudo"
    command.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have
    authorization.
    When operating systems provide the capability to escalate a functional capability, it is critical the organization
    requires the user to re-authenticate when using the "sudo" command.
    If the value is set to an integer less than 0, the user\'s time stamp will not expire and the user will not have to
    re-authenticate for privileged actions until the user\'s session is terminated.'
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000373-GPOS-00156'
  tag 'satisfies': nil
  tag 'gid': 'V-237635'
  tag 'rid': 'SV-237635r646856_rule'
  tag 'stig_id': 'RHEL-07-010343'
  tag 'fix_id': 'F-40817r646855_fix'
  tag 'cci': ['CCI-002038']
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
  tag 'check': 'Verify the operating system requires re-authentication when using the "sudo" command to elevate
    privileges.
    $ sudo grep -i \'timestamp_timeout\' /etc/sudoers /etc/sudoers.d/*
    /etc/sudoers:Defaults timestamp_timout=0
    If "timestamp_timeout" is set to a negative number, is commented out, or no results are returned, this is a
    finding.'
  tag 'fix': 'Configure the "sudo" command to require re-authentication.
    Edit the /etc/sudoers file:
    $ sudo visudo
    Add or modify the following line:
    Defaults timestamp_timeout=[value]
    Note: The "[value]" must be a number that is greater than or equal to "0".'

  describe command('grep -i \'timestamp_timeout\' /etc/sudoers /etc/sudoers.d/*') do
    its('stdout') { should_not be nil }
    its('stdout') { should_not match /#/ }
    its('stdout') { should_not match /-/ }
  end
end

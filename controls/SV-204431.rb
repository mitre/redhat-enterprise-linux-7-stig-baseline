control 'SV-204431' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the delay between logon prompts
    following a failed console logon attempt is at least four seconds.'
  desc "Configuring the operating system to implement organization-wide security implementation guides and security
    checklists verifies compliance with federal standards and establishes a common security baseline across #{input('org_name')[:acronym]} that
    reflects the most restrictive security posture consistent with operational requirements.
    Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components
    of the system that affect the security posture and/or functionality of the system. Security-related parameters are
    those parameters impacting the security state of the system, including the parameters required to satisfy other
    security control requirements. Security-related parameters include, for example, registry settings; account, file,
    and directory permission settings; and settings for functions, ports, protocols, services, and remote connections."
  desc 'check', 'Verify the operating system enforces a delay of at least four seconds between console logon prompts
    following a failed logon attempt.
    Check the value of the "fail_delay" parameter in the "/etc/login.defs" file with the following command:
    # grep -i fail_delay /etc/login.defs
    FAIL_DELAY 4
    If the value of "FAIL_DELAY" is not set to "4" or greater, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce a delay of at least four seconds between logon prompts
    following a failed console logon attempt.
    Modify the "/etc/login.defs" file to set the "FAIL_DELAY" parameter to "4" or greater:
    FAIL_DELAY 4'
  impact 0.5
  tag legacy: ['SV-86575', 'V-71951']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag gid: 'V-204431'
  tag rid: 'SV-204431r603261_rule'
  tag stig_id: 'RHEL-07-010430'
  tag fix_id: 'F-4555r88486_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['login_defs']
  tag 'host'
  tag 'container'

  describe login_defs do
    its('FAIL_DELAY') { should cmp >= input('fail_delay') }
    its('FAIL_DELAY') { should_not be_nil }
  end
end

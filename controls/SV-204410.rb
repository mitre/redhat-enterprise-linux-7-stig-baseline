control 'SV-204410' do
  title "The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new
    passwords are established, the new password must contain at least #{input('min_special_characters')} special character."
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password.
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing
    and brute-force attacks.
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex
    the password, the greater the number of possible combinations that need to be tested before the password is
    compromised.'
  desc 'check', "Verify the operating system enforces password complexity by requiring that at least #{input('min_special_characters')} special
    character be used.
    Note: The value to require a number of special characters to be set is expressed as a negative number in
    \"/etc/security/pwquality.conf\".
    Check the value for \"ocredit\" in \"/etc/security/pwquality.conf\" with the following command:
    # grep ocredit /etc/security/pwquality.conf
    ocredit=-#{input('min_special_characters')}
    If the value of \"ocredit\" is not set to a negative value, this is a finding."
  desc 'fix', "Configure the operating system to enforce password complexity by requiring that at least #{input('min_special_characters')} special
    character be used by setting the \"ocredit\" option.
    Add the following line to \"/etc/security/pwquality.conf\" (or modify the line to have the required value):
    ocredit = -#{input('min_special_characters')}"
  impact 0.5
  tag legacy: ['SV-86533', 'V-71909']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag gid: 'V-204410'
  tag rid: 'SV-204410r603261_rule'
  tag stig_id: 'RHEL-07-010150'
  tag fix_id: 'F-4534r88423_fix'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
  tag subsystems: ['pwquality', 'password']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/security/pwquality.conf') do
    its('ocredit') { should cmp <= -input('min_special_characters') }
  end
end

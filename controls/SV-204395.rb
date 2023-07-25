control 'SV-204395' do
  title "The Red Hat Enterprise Linux operating system must display the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent
    Banner before granting local or remote access to the system via a command line user logon."
  desc "Display of a standardized and approved use notification before granting access to the operating system
    ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive
    Orders, directives, policies, regulations, standards, and guidance.
    System use notifications are required only for access via logon interfaces with human users and are not required
    when such human interfaces do not exist.
    The banner must be formatted in accordance with applicable #{input('org_name')[:acronym]} policy. Use the following verbiage for operating
    systems that can accommodate banners of 1300 characters:
    \"#{input('banner_message_text_cli')}\""
  desc 'rationale', ''
  desc 'check', "Verify the operating system displays the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner before
    granting access to the operating system via a command line user logon.
    Check to see if the operating system displays a banner at the command line logon screen with the following command:
    # more /etc/issue
    The command should return the following text:
    \"#{input('banner_message_text_cli')}\"
    If the operating system does not display a graphical logon banner or the banner does not match the Standard
    Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner, this is a finding.
    If the text in the \"/etc/issue\" file does not match the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner, this is a
    finding."
  desc 'fix', "Configure the operating system to display the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner before
    granting access to the system via the command line by editing the \"/etc/issue\" file.
    Replace the default text with the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner. The #{input('org_name')[:acronym]} required text is:
    \"#{input('banner_message_text_cli')}\" "
  impact 0.5
  tag legacy: ['V-71863', 'SV-86487']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007']
  tag gid: 'V-204395'
  tag rid: 'SV-204395r603261_rule'
  tag stig_id: 'RHEL-07-010050'
  tag fix_id: 'F-4519r88378_fix'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
  tag subsystems: ['banner', '/etc/issue']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else

    banner_message_text_cli = input('banner_message_text_cli')
    banner_message_text_cli_limited = input('banner_message_text_cli_limited')

    clean_banner = banner_message_text_cli.gsub(/[\r\n\s]/, '')
    clean_banner_limited = banner_message_text_cli_limited.gsub(/[\r\n\s]/,
                                                                '')
    banner_file = file('/etc/issue')
    banner_missing = !banner_file.exist?

    if banner_missing
      describe 'The banner text is not set because /etc/issue does not exist' do
        subject { banner_missing }
        it { should be false }
      end
    end

    banner_message = banner_file.content.gsub(/[\r\n\s]/, '')
    unless banner_missing
      describe.one do
        describe 'The banner text should match the standard banner' do
          subject { banner_message }
          it { should cmp clean_banner }
        end
        describe 'The banner text should match the limited banner' do
          subject { banner_message }
          it { should cmp clean_banner_limited }
        end
      end
    end
  end
end

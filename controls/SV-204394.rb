control 'SV-204394' do
  title "The Red Hat Enterprise Linux operating system must display the approved Standard Mandatory #{input('org_name')[:acronym]} Notice and
    Consent Banner before granting local or remote access to the system via a graphical user logon."
  desc "Display of a standardized and approved use notification before granting access to the operating system
    ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive
    Orders, directives, policies, regulations, standards, and guidance.
    System use notifications are required only for access via logon interfaces with human users and are not required
    when such human interfaces do not exist.
    The banner must be formatted in accordance with applicable #{input('org_name')[:acronym]} policy.
    \"#{input('banner_message_text_gui')}\" "
  desc 'check', "Verify the operating system displays the approved Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner
    before granting access to the operating system via a graphical user logon.
    Note: If the system does not have a Graphical User Interface installed, this requirement is Not Applicable.
    Check that the operating system displays the exact approved Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner text
    with the command:
    # grep banner-message-text /etc/dconf/db/local.d/*
    banner-message-text='#{input('banner_message_text_gui')}'
    Note: The \"\\n \" characters are for formatting only. They will not be displayed on the Graphical User Interface.
    If the banner does not match the approved Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner, this is a finding."
  desc 'fix', "Configure the operating system to display the approved Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent
    Banner before granting access to the system.
    Note: If the system does not have a Graphical User Interface installed, this requirement is Not Applicable.
    Create a database to contain the system-wide graphical user logon settings (if it does not already exist) with the
    following command:
    # touch /etc/dconf/db/local.d/01-banner-message
    Add the following line to the [org/gnome/login-screen] section of the \"/etc/dconf/db/local.d/01-banner-message\":
    [org/gnome/login-screen]
    banner-message-enable=true
    banner-message-text='#{input('banner_message_text_gui')}'
    Note: The \"\\n \" characters are for formatting only. They will not be displayed on the Graphical User Interface.
    Run the following command to update the database:
    # dconf update"
  impact 0.5
  tag legacy: ['V-71861', 'SV-86485']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-204394'
  tag rid: 'SV-204394r603261_rule'
  tag stig_id: 'RHEL-07-010040'
  tag fix_id: 'F-4518r297479_fix'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
  tag subsystems: ['gdm']
  tag 'host'

  if package('gnome-desktop3').installed?
    # Get all files that have the banner-message-text specified.
    banner_files =
      command('grep -l banner-message-text /etc/dconf/db/local.d/*').stdout.split("\n")
    # If there are no banner files then this is a finding.
    banner_missing = banner_files.empty?
    if banner_missing
      describe 'If no files specify the banner text then this is a finding' do
        subject { banner_missing }
        it { should be false }
      end
    end
    # If there are banner files then check them to make sure they have the correct text.
    banner_files.each do |banner_file|
      banner_message =
        parse_config_file(banner_file).params('org/gnome/login-screen', 'banner-message-text').gsub(
          /[\r\n\s]/, ''
        )
      # dconf expects the banner-message-text to be quoted so remove leading and trailing quote.
      # See https://developer.gnome.org/dconf/unstable/dconf-tool.html which states:
      #  VALUE arguments must be in GVariant format, so e.g. a string must include
      #  explicit quotes: "'foo'". This format is also used when printing out values.
      if banner_message.start_with?('"') || banner_message.start_with?('\'')
        banner_message = banner_message[1, banner_message.length]
      end
      if banner_message.end_with?('"') || banner_message.end_with?('\'')
        banner_message = banner_message.chop
      end
      banner_message.gsub!('\\n', '')
      foo = input('banner_message_text_gui')
      foo2 = input('banner_message_text_gui_limited')
      describe.one do
        describe banner_message do
          it { should cmp foo.gsub(/[\r\n\s]/, '') }
        end
        describe banner_message do
          it { should cmp foo2.gsub(/[\r\n\s]/, '') }
        end
      end
    end
  else
    impact 0.0
    describe 'The system does not have GNOME installed' do
      skip "The system does not have GNOME installed, this requirement is Not
        Applicable."
    end
  end
end

control 'SV-204393' do
  title "The Red Hat Enterprise Linux operating system must display the Standard Mandatory #{input('org_name')} Notice and Consent
    Banner before granting local or remote access to the system via a graphical user logon."
  desc "Display of a standardized and approved use notification before granting access to the operating system
    ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive
    Orders, directives, policies, regulations, standards, and guidance.
    System use notifications are required only for access via logon interfaces with human users and are not required
    when such human interfaces do not exist.
    The banner must be formatted in accordance with applicable #{input('org_name')} policy. Use the following verbiage for operating
    systems that can accommodate banners of 1300 characters:
    \"#{input('banner_message_text_gui')}\" "
  desc 'rationale', ''
  desc 'check',"Verify the operating system displays the Standard Mandatory #{input('org_name')} Notice and Consent Banner before
    granting access to the operating system via a graphical user logon.
    Note: If the system does not have GNOME installed, this requirement is Not Applicable.
    Check to see if the operating system displays a banner at the logon screen with the following command:
    # grep banner-message-enable /etc/dconf/db/local.d/*
    banner-message-enable=true
    If \"banner-message-enable\" is set to \"false\" or is missing, this is a finding."
  desc 'fix', "Configure the operating system to display the Standard Mandatory #{input('org_name')} Notice and Consent Banner before
    granting access to the system.
    Note: If the system does not have GNOME installed, this requirement is Not Applicable.
    Create a database to contain the system-wide graphical user logon settings (if it does not already exist) with the
    following command:
    # touch /etc/dconf/db/local.d/01-banner-message
    Add the following line to the [org/gnome/login-screen] section of the \"/etc/dconf/db/local.d/01-banner-message\":
    [org/gnome/login-screen]
    banner-message-enable=true
    Update the system databases:
    # dconf update
    Users must log out and back in again before the system-wide settings take effect."
  impact 0.5
  tag legacy: ['V-71859', 'SV-86483']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-204393'
  tag rid: 'SV-204393r603261_rule'
  tag stig_id: 'RHEL-07-010030'
  tag fix_id: 'F-4517r88372_fix'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
  tag subsystems: ['gui', 'banner']

  if package('gnome-desktop3').installed?
    if !input('dconf_user').nil? and command('whoami').stdout.strip == 'root'
      describe command("sudo -u input('dconf_user') dconf read /org/gnome/login-screen/banner-message-enable") do
        its('stdout.strip') do
          should cmp input('banner_message_enabled').to_s
        end
      end
    else
      describe command('dconf read /org/gnome/login-screen/banner-message-enable') do
        its('stdout.strip') do
          should cmp input('banner_message_enabled').to_s
        end
      end
    end
  else
    impact 0.0
    describe 'The GNOME desktop is not installed' do
      skip 'The GNOME desktop is not installed, this control is Not Applicable.'
    end
  end
end

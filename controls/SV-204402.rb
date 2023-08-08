control 'SV-204402' do
  title 'The Red Hat Enterprise Linux operating system must initiate a session lock for the screensaver after a
    period of inactivity for graphical user interfaces.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate
    physical vicinity of the information system but does not log out because of the temporary nature of the absence.
    Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity,
    operating systems need to be able to identify when a user's session has idled and take action to initiate the
    session lock.
    The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', "Verify the operating system initiates a session lock after a #{input('system_activity_timeout')/60}-minute period of inactivity for graphical user interfaces.

Note: If the system does not have a GNOME installed, this requirement is Not Applicable.

Check for the session lock settings with the following commands:

     # grep -i idle-activation-enabled /etc/dconf/db/local.d/*
     idle-activation-enabled=true
     
If \"idle-activation-enabled\" is not set to \"true\", this is a finding."
  desc 'fix', "Configure the operating system to initiate a session lock after a #{input('system_activity_timeout')/60}-minute period of inactivity for
    graphical user interfaces.
    Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following
    command:
    # touch /etc/dconf/db/local.d/00-screensaver
    Add the setting to enable screensaver locking after #{input('system_activity_timeout')/60} minutes of inactivity:
    [org/gnome/desktop/screensaver]
    idle-activation-enabled=true
    Update the system databases:
    # dconf update
    Users must log out and back in again before the system-wide settings take effect."
  impact 0.5
  tag legacy: ['V-71899', 'SV-86523']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag gid: 'V-204402'
  tag rid: 'SV-204402r880782_rule'
  tag stig_id: 'RHEL-07-010100'
  tag fix_id: 'F-4526r880781_fix'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
  tag subsystems: ['gui', 'session', 'lock']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  elsif package('gnome-desktop3').installed?

    describe command('gsettings get org.gnome.desktop.screensaver idle-activation-enabled') do
      its('stdout.strip') { should cmp 'true' }
    end
  else
    impact 0.0
    describe 'The system does not have GNOME installed' do
      skip "The system does not have GNOME installed, this requirement is Not
        Applicable."
    end
  end
end

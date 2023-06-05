control 'SV-256969' do
  title 'The Red Hat Enterprise Linux operating system must disable the login screen user list for graphical user interfaces.'
  desc 'Leaving the user list enabled is a security risk as it allows anyone with physical access to the system to enumerate known user accounts without authenticated access to the system.'
  desc 'check', 'Verify that the operating system is configured to disable the login screen user list for graphical user interfaces.

Note: If the system does not have the GNOME Desktop installed, this requirement is Not Applicable.

Verify that the login screen user list for the GNOME Desktop is disabled with the following command:

     $ sudo grep -is disable-user-list /etc/dconf/db/gdm.d/*
     
     /etc/dconf/db/gdm.d/00-login-screen:disable-user-list=true
	 
If the variable "disable-user-list" is not defined in a file under "/etc/dconf/db/gdm.d/", is not set to "true", is missing or commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the login screen user list for graphical user interfaces.

Create or edit the gdm profile in "/etc/dconf/profile/" to contain the following lines:

     $ sudo vi /etc/dconf/profile/gdm
	 
     user-db:user
     system-db:gdm
     file-db:/usr/share/gdm/greeter-dconf-defaults
	 
Create or edit the gdm database for machine-wide settings in "/etc/dconf/db/gdm.d/" with the following lines:

     $ sudo vi /etc/dconf/db/gdm.d/00-login-screen
	 
     [org/gnome/login-screen]
     disable-user-list=true
	 
Update the system databases by updating the dconf utility:

     $ sudo dconf update
	 
If the login screen user list persists after updating the system databases, you can restart the GNOME Desktop without rebooting the system:

     $ sudo systemctl restart gdm'
  impact 0.5
  tag check_id: 'C-60647r902688_chk'
  tag severity: 'medium'
  tag gid: 'V-256969'
  tag rid: 'SV-256969r902690_rule'
  tag stig_id: 'RHEL-07-010063'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60589r902689_fix'
  tag documentable: nil
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

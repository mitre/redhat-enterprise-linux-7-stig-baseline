control 'SV-244557' do
  title 'Red Hat Enterprise Linux operating systems version 7.2 or newer booted with a BIOS must have a unique name for the grub superusers account when booting into single-user and maintenance modes.'
  desc 'If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.
The GRUB 2 superuser account is an account of last resort. Establishing a unique username for this account hardens the boot loader against brute force attacks. Due to the nature of the superuser account database being distinct from the OS account database, this allows the use of a username that is not among those within the OS account database. Examples of non-unique superusers names are root, superuser, unlock, etc.'
  desc 'check', 'For systems that use UEFI, this is Not Applicable.

For systems that are running a version of RHEL prior to 7.2, this is Not Applicable.

Verify that a unique name is set as the "superusers" account:

# grep -iw "superusers" /boot/grub2/grub.cfg
    set superusers="[someuniquestringhere]"
    export superusers

If "superusers" is identical to any OS account name or is missing a name, this is a finding.'
  desc 'fix', 'Configure the system to have a unique name for the grub superusers account.

Edit the /boot/grub2/grub.cfg file and add or modify the following lines in the "### BEGIN /etc/grub.d/01_users ###" section:

set superusers="[someuniquestringhere]"
export superusers
password_pbkdf2 [someuniquestringhere] ${GRUB2_PASSWORD}'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'V-244557'
  tag rid: 'SV-244557r792838_rule'
  tag stig_id: 'RHEL-07-010483'
  tag fix_id: 'F-47789r744062_fix'
  tag cci: ['CCI-000213']
  tag legacy: []
  tag subsystems: ['grub']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  elsif file('/sys/firmware/efi').exist?
    impact 0.0
    describe 'System running UEFI' do
      skip 'The System is running UEFI, this control is Not Applicable.'
    end
  elsif os[:release] >= '7.2'
    options = {
        assignment_regex: /^\s*(.*)=\"?([^\"]+)\"?$/
      }

    describe parse_config_file(input('grub_main_cfg'), options) do
      its('set superusers') { should_not be nil }
      its('set superusers') { should_not be_in users.usernames }
    end

  else
    impact 0.0
    describe 'System running version of RHEL prior to 7.2' do
      skip 'The System is running an outdated version of RHEL, this control is Not Applicable.'
    end
  end
end

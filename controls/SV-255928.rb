control 'SV-255928' do
  title 'The Red Hat Enterprise Linux operating system must be configured to prevent overwriting of custom authentication configuration settings by the authconfig utility.'
  desc 'When using the authconfig utility to modify authentication configuration settings, the "system-auth" and "password-auth" files and any custom settings that they may contain are overwritten. This can be avoided by creating new local configuration files and creating new or moving existing symbolic links to them. The authconfig utility will recognize the local configuration files and not overwrite them, while writing its own settings to the original configuration files.'
  desc 'check', 'Verify "system-auth" and "password-auth" files are symbolic links pointing to "system-auth-local" and "password-auth-local":
     $ sudo ls -l /etc/pam.d/{password,system}-auth

     lrwxrwxrwx. 1 root root 30 Apr 1 11:59 /etc/pam.d/password-auth -> /etc/pam.d/password-auth-local
     lrwxrwxrwx. 1 root root 28 Apr 1 11:59 /etc/pam.d/system-auth -> /etc/pam.d/system-auth-local

If system-auth and password-auth files are not symbolic links, this is a finding.

If system-auth and password-auth are symbolic links but do not point to "system-auth-local" and "password-auth-local", this is a finding.'
  desc 'fix', 'Create custom configuration files and their corresponding symbolic links:

Rename the existing configuration files (skip this step if symbolic links are already present):
     $ sudo mv /etc/pam.d/system-auth /etc/pam.d/system-auth-ac
     $ sudo mv /etc/pam.d/password-auth /etc/pam.d/password-auth-ac

Create custom system-auth configuration file:
     $ sudo vi /etc/pam.d/system-auth-local

The new file, at minimum, must contain the following lines:

auth        required      pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
auth        include       system-auth-ac
auth        sufficient    pam_unix.so try_first_pass
auth        [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900

account     required      pam_faillock.so
account     include       system-auth-ac

password    requisite     pam_pwhistory.so use_authtok remember=5 retry=3
password    include       system-auth-ac
password    sufficient    pam_unix.so sha512 shadow try_first_pass use_authtok

session     include       system-auth-ac

Create custom password-auth configuration file:
     $ sudo vi /etc/pam.d/password-auth-local

The new file, at minimum, must contain the following lines:

auth        required      pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=900
auth        include       password-auth-ac
auth        sufficient    pam_unix.so try_first_pass
auth        [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900

account     required      pam_faillock.so
account     include       password-auth-ac

password    requisite     pam_pwhistory.so use_authtok remember=5 retry=3
password    include       password-auth-ac
password    sufficient    pam_unix.so sha512 shadow try_first_pass use_authtok

session     include       password-auth-ac

Create new or move existing symbolic links to the new custom configuration files:
     $ sudo ln -sf /etc/pam.d/system-auth-local /etc/pam.d/system-auth
     $ sudo ln -sf /etc/pam.d/password-auth-local /etc/pam.d/password-auth

Once finished you should have the following file structure:
    $ sudo ls -1 /etc/pam.d/{password,system}-auth*

    /etc/pam.d/password-auth
    /etc/pam.d/password-auth-ac
    /etc/pam.d/password-auth-local
    /etc/pam.d/system-auth
    /etc/pam.d/system-auth-ac
    /etc/pam.d/system-auth-local

Done.

Note: With this solution in place any custom settings to "system-auth" and "password-auth" will be retained and not overwritten by the use of the authconfig utility.  The authconfig utility will write its settings to "system-auth-ac" and "password-auth-ac" and continue to function as expected.'
  impact 0.5
  tag check_id: 'C-59605r880828_chk'
  tag severity: 'medium'
  tag gid: 'V-255928'
  tag rid: 'SV-255928r880830_rule'
  tag stig_id: 'RHEL-07-010199'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-59548r880829_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']

  describe file('/etc/pam.d/system-auth') do
    it { should be_symlink }
    its('link_path') { should cmp '/etc/pam.d/system-auth-local' }
  end

  if file('/etc/pam.d/system-auth').symlink? && file('/etc/pam.d/system-auth').link_path == '/etc/pam.d/system-auth-local'
    describe '/etc/pam.d/system-auth-local should contain the minimum configuration settings' do
      subject { parse_config_file('/etc/pam.d/system-auth-local').content.strip }
      it { should match /auth.*required.*pam_faillock.so.*preauth.*silent.*audit.*deny=3.*even_deny_root.*fail_interval=900.*unlock_time=900/ }
      it { should match /auth.*include.*system-auth-ac/ }
      it { should match /auth.*sufficient.*pam_unix.so.*try_first_pass/ }
      it { should match /auth.*default=die.*pam_faillock.so.*authfail.*audit.*deny=3.*even_deny_root.*fail_interval=900.*unlock_time=900/ }
      it { should match /account.*required.*pam_faillock.so/ }
      it { should match /account.*include.*system-auth-ac/ }
      it { should match /password.*requisite.*pam_pwhistory.so.*use_authtok.*remember=5.*retry=3/ }
      it { should match /password.*include.*system-auth-ac/ }
      it { should match /password.*sufficient.*pam_unix.so.*sha512.*shadow.*try_first_pass.*use_authtok/ }
      it { should match /session.*include.*system-auth-ac/ }
    end
  end

  describe file('/etc/pam.d/password-auth') do
    it { should be_symlink }
    its('link_path') { should cmp '/etc/pam.d/password-auth-local' }
  end

  if file('/etc/pam.d/password-auth').symlink? && file('/etc/pam.d/password-auth').link_path == '/etc/pam.d/password-auth-local'

    describe '/etc/pam.d/password-auth-local should contain the minimum configuration settings' do
      subject { parse_config_file('/etc/pam.d/password-auth-local').content.strip }
      it { should match /auth.*required.*pam_faillock.so.*preauth.*silent.*audit.*deny=3.*even_deny_root.*fail_interval=900.*unlock_time=900/ }
      it { should match /auth.*include.*password-auth-ac/ }
      it { should match /auth.*sufficient.*pam_unix.so.*try_first_pass/ }
      it { should match /auth.*default=die.*pam_faillock.so.*authfail.*audit.*deny=3.*even_deny_root.*fail_interval=900.*unlock_time=900/ }
      it { should match /account.*required.*pam_faillock.so/ }
      it { should match /account.*include.*password-auth-ac/ }
      it { should match /password.*requisite.*pam_pwhistory.so.*use_authtok.*remember=5.*retry=3/ }
      it { should match /password.*include.*password-auth-ac/ }
      it { should match /password.*sufficient.*pam_unix.so.*sha512.*shadow.*try_first_pass.*use_authtok/ }
      it { should match /session.*include.*password-auth-ac/ }
    end
  end
end

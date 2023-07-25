control 'SV-204580' do
  title "The Red Hat Enterprise Linux operating system must display the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent
    Banner immediately prior to, or as part of, remote access logon prompts."
  desc "Display of a standardized and approved use notification before granting access to the publicly accessible
    operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws,
    Executive Orders, directives, policies, regulations, standards, and guidance.
    System use notifications are required only for access via logon interfaces with human users and are not required
    when such human interfaces do not exist.
    The banner must be formatted in accordance with applicable #{input('org_name')[:acronym]} policy. Use the following verbiage for operating
    systems that can accommodate banners of 1300 characters:
    \"#{input('banner_message_text_ral')}\" "
  desc 'check', "Verify any publicly accessible connection to the operating system displays the Standard Mandatory
    #{input('org_name')[:acronym]} Notice and Consent Banner before granting access to the system.
    Check for the location of the banner file being used with the following command:
    # grep -i banner /etc/ssh/sshd_config
    banner /etc/issue
    This command will return the banner keyword and the name of the file that contains the ssh banner (in this case
    \"/etc/issue\").
    If the line is commented out, this is a finding.
    View the file specified by the banner keyword to check that it matches the text of the Standard Mandatory #{input('org_name')[:acronym]} Notice
    and Consent Banner:
    \"#{input('banner_message_text_ral')}\"
    If the system does not display a graphical logon banner or the banner does not match the Standard Mandatory #{input('org_name')[:acronym]}
    Notice and Consent Banner, this is a finding.
    If the text in the file does not match the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner, this is a finding."
  desc 'fix', "Configure the operating system to display the Standard Mandatory #{input('org_name')[:acronym]} Notice and Consent Banner before
    granting access to the system via the ssh.
    Edit the \"/etc/ssh/sshd_config\" file to uncomment the banner keyword and configure it to point to a file that will
    contain the logon banner (this file may be named differently or be in a different location if using a version of SSH
    that is provided by a third-party vendor). An example configuration line is:
    banner /etc/issue
    Either create the file containing the banner or replace the text in the file with the Standard Mandatory #{input('org_name')[:acronym]} Notice
    and Consent Banner. The #{input('org_name')[:acronym]} required text is:
    \"#{input('banner_message_text_ral')}\"
    The SSH service must be restarted for changes to take effect."
  impact 0.5
  tag legacy: ['V-72225', 'SV-86849']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000024-GPOS-00007', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-204580'
  tag rid: 'SV-204580r603261_rule'
  tag stig_id: 'RHEL-07-040170'
  tag fix_id: 'F-4704r297486_fix'
  tag cci: ['CCI-000048', 'CCI-000050', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 b', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
  tag subsystems: ['ssh', 'banner']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  else

    banner_message_text_ral = input('banner_message_text_ral')
    banner_message_text_ral_limited = input('banner_message_text_ral_limited')

    # When Banner is commented, not found, disabled, or the specified file does not exist, this is a finding.
    banner_files = [sshd_config.banner].flatten

    banner_files.each do |banner_file|
      # Banner property is commented out.
      if banner_file.nil?
        describe 'The SSHD Banner is not set' do
          subject { banner_file.nil? }
          it { should be false }
        end
      end

      # Banner property is set to "none"
      if !banner_file.nil? && !banner_file.match(/none/i).nil?
        describe 'The SSHD Banner is disabled' do
          subject { banner_file.match(/none/i).nil? }
          it { should be true }
        end
      end

      # Banner property provides a path to a file, however, it does not exist.
      if !banner_file.nil? && banner_file.match(/none/i).nil? && !file(banner_file).exist?
        describe 'The SSHD Banner is set, but, the file does not exist' do
          subject { file(banner_file).exist? }
          it { should be true }
        end
      end

      # Banner property provides a path to a file and it exists.
      unless !banner_file.nil? && banner_file.match(/none/i).nil? && file(banner_file).exist?
        next
      end

      describe.one do
        banner = file(banner_file).content.gsub(/[\r\n\s]/, '')
        clean_banner = banner_message_text_ral.gsub(/[\r\n\s]/, '')
        clean_banner_limited = banner_message_text_ral_limited.gsub(/[\r\n\s]/,
                                                                    '')

        describe 'The SSHD Banner is set to the standard banner and has the correct text' do
          subject { banner }
          it { should cmp clean_banner }
        end

        describe 'The SSHD Banner is set to the standard limited banner and has the correct text' do
          subject { banner }
          it { should cmp clean_banner_limited }
        end
      end
    end
  end
end

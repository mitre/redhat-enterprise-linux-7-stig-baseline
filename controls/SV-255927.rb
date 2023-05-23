control 'SV-255927' do
  title 'The Red Hat Enterprise Linux operating system must restrict access to the kernel message buffer.'
  desc 'Restricting access to the kernel message buffer limits access only to root. This prevents attackers from gaining additional system information as a non-privileged user.'
  desc 'check', 'Verify the operating system is configured to restrict access to the kernel message buffer with the following commands:

     $ sudo sysctl kernel.dmesg_restrict
     kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter:

     $ sudo grep -r kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
     /etc/sysctl.conf:kernel.dmesg_restrict = 1
     /etc/sysctl.d/99-sysctl.conf:kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the operating system to restrict access to the kernel message buffer.

Set the system to the required kernel parameter by adding or modifying the following line in /etc/sysctl.conf or a config file in the /etc/sysctl.d/ directory:

     kernel.dmesg_restrict = 1

Remove any configurations that conflict with the above from the following locations:
     /run/sysctl.d/
     /etc/sysctl.d/
     /usr/local/lib/sysctl.d/
     /usr/lib/sysctl.d/
     /lib/sysctl.d/
     /etc/sysctl.conf

Reload settings from all system configuration files with the following command:

     $ sudo sysctl --system'
  impact 0.3
  tag check_id: 'C-59604r880789_chk'
  tag severity: 'low'
  tag gid: 'V-255927'
  tag rid: 'SV-255927r880791_rule'
  tag stig_id: 'RHEL-07-010375'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-59547r880790_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    dmesg_restrict = 1
    config_file_values = command('grep -r kernel.dmesg_restrict /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null')
                         .stdout.strip.split("\n")
                         .map { |file| parse_config(file).params }
    config_file_values_uncompliant = config_file_values.select { |entry| entry.values != [dmesg_restrict.to_s] }

    unless config_file_values_uncompliant.empty?
      describe 'All configuration files' do
        it "should set dmesg_restrict to #{dmesg_restrict}, or not define it at all" do
          fail_msg = "Found incorrect configuration:\n#{config_file_values_uncompliant.join("\n")}"
          expect(config_file_values_uncompliant).to be_empty, fail_msg
        end
      end
    end

    describe 'The runtime kernel parameter kernel.dmesg_restrict' do
      subject { kernel_parameter('kernel.dmesg_restrict') }
      its('value') { should eq dmesg_restrict }
    end
  end
end

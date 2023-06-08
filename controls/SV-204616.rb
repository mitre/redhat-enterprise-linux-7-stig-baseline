control 'SV-204616' do
  title 'The Red Hat Enterprise Linux operating system must not allow interfaces to perform Internet Protocol
    version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects by default.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular
    destination. These messages contain information from the system's route table, possibly revealing portions of the
    network topology."
  desc 'check', 'Verify the system does not allow interfaces to perform IPv4 ICMP redirects by default.

     # grep -r net.ipv4.conf.default.send_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null

If "net.ipv4.conf.default.send_redirects" is not configured in the "/etc/sysctl.conf" file or in any of the other sysctl.d directories, is commented out or does not have a value of "0", this is a finding.

Check that the operating system implements the "default send_redirects" variables with the following command:

     # /sbin/sysctl -a | grep net.ipv4.conf.default.send_redirects
     net.ipv4.conf.default.send_redirects = 0

If the returned line does not have a value of "0", this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the system to not allow interfaces to perform IPv4 ICMP redirects by default.
    Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a
    configuration file in the /etc/sysctl.d/ directory (or modify the line to have the required value):
    net.ipv4.conf.default.send_redirects = 0
    Issue the following command to make the changes take effect:
    # sysctl --system'
  impact 0.5
  tag legacy: ['V-72291', 'SV-86915']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204616'
  tag rid: 'SV-204616r880818_rule'
  tag stig_id: 'RHEL-07-040650'
  tag fix_id: 'F-4740r880817_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['kernel_parameter', 'ipv4']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable - Kernel config must be done on the host' do
      skip 'Control not applicable - Kernel config must be done on the host'
    end
  else
    send_redirects = 0
    config_file_values = command('grep -r net.ipv4.conf.default.send_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null')
                         .stdout.strip.split("\n")
                         .map { |file| parse_config(file).params }
    config_file_values_uncompliant = config_file_values.select { |entry| entry.values != [send_redirects.to_s] }

    unless config_file_values_uncompliant.empty?
      describe 'All configuration files' do
        it "should set send_redirects to #{send_redirects}, or not define it at all" do
          fail_msg = "Found incorrect configuration:\n#{config_file_values_uncompliant.join("\n")}"
          expect(config_file_values_uncompliant).to be_empty, fail_msg
        end
      end
    end

    describe 'The runtime kernel parameter net.ipv4.conf.default.send_redirects' do
      subject { kernel_parameter('net.ipv4.conf.default.send_redirects') }
      its('value') { should eq send_redirects }
    end
  end
end

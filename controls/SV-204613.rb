control 'SV-204613' do
  title 'The Red Hat Enterprise Linux operating system must not respond to Internet Protocol version 4 (IPv4)
    Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc 'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification
    attacks.'
  desc 'check', 'Verify the system does not respond to IPv4 ICMP echoes sent to a broadcast address.

     # grep -r net.ipv4.icmp_echo_ignore_broadcasts /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null

If "net.ipv4.icmp_echo_ignore_broadcasts" is not configured in the /etc/sysctl.conf file or in any of the other sysctl.d directories, is commented out, or does not have a value of "1", this is a finding.

Check that the operating system implements the "icmp_echo_ignore_broadcasts" variable with the following command:

     # /sbin/sysctl -a | grep net.ipv4.icmp_echo_ignore_broadcasts
     net.ipv4.icmp_echo_ignore_broadcasts = 1

If the returned line does not have a value of "1", this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Set the system to the required kernel parameter by adding the following
line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/
directory (or modify the line to have the required value):

    net.ipv4.icmp_echo_ignore_broadcasts = 1

    Issue the following command to make the changes take effect:

    # sysctl --system'
  impact 0.5
  tag legacy: ['V-72287', 'SV-86911']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204613'
  tag rid: 'SV-204613r880809_rule'
  tag stig_id: 'RHEL-07-040630'
  tag fix_id: 'F-4737r880808_fix'
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
    results_in_files = command('grep -r net.ipv4.icmp_echo_ignore_broadcasts /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null').stdout.strip.split("\n")

    values = []
    results_in_files.each { |result| values.append(parse_config(result).params.values) }

    icmp_echo_ignore_broadcasts = 1
    unique_values = values.uniq.flatten
    describe 'net.ipv4.icmp_echo_ignore_broadcasts' do
      it "should be set to #{icmp_echo_ignore_broadcasts} in the configuration files" do
        conflicting_values_fail_message = "net.ipv4.icmp_echo_ignore_broadcasts is set to conflicting values as follows: #{unique_values}"
        incorrect_value_fail_message = "The net.ipv4.icmp_echo_ignore_broadcasts value is set to #{unique_values[0]} and should be set to #{icmp_echo_ignore_broadcasts}"
        unless unique_values.empty?
          expect(unique_values.length).to cmp(1), conflicting_values_fail_message
          expect(unique_values[0]).to cmp(icmp_echo_ignore_broadcasts), incorrect_value_fail_message
        end
      end
    end

    describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
      its('value') { should eq icmp_echo_ignore_broadcasts }
    end
  end
end

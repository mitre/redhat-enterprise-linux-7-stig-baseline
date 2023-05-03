control 'SV-204610' do
  title 'The Red Hat Enterprise Linux operating system must use a reverse-path filter for IPv4 network traffic when
    possible on all interfaces.'
  desc 'Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems that are routers for complicated networks, but is helpful for end hosts and routers serving small networks.'
  desc 'check', 'Verify the system uses a reverse-path filter for IPv4:

     # grep -r net.ipv4.conf.all.rp_filter /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
     net.ipv4.conf.all.rp_filter = 1

If "net.ipv4.conf.all.rp_filter" is not configured in the /etc/sysctl.conf file or in any of the other sysctl.d directories, is commented out, or does not have a value of "1", this is a finding.

Check that the operating system implements the accept source route variable with the following command:

     # /sbin/sysctl -a | grep net.ipv4.conf.all.rp_filter
     net.ipv4.conf.all.rp_filter = 1

If the returned line does not have a value of "1", this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Set the system to the required kernel parameter by adding the following
line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/
directory (or modify the line to have the required value):

    net.ipv4.conf.all.rp_filter = 1

    Issue the following command to make the changes take effect:

    # sysctl --system'
  impact 0.5
  tag legacy: ['V-92251', 'SV-102353']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204610'
  tag rid: 'SV-204610r880800_rule'
  tag stig_id: 'RHEL-07-040611'
  tag fix_id: 'F-4734r880799_fix'
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
    results_in_files = command('grep -r net.ipv4.conf.all.rp_filter /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null').stdout.strip.split("\n")

    values = []
    results_in_files.each { |result| values.append(parse_config(result).params.values) }

    rp_filter = 1
    unique_values = values.uniq.flatten
    describe 'net.ipv4.conf.all.rp_filter' do
      it "should be set to #{rp_filter} in the configuration files" do
        conflicting_values_fail_message = "net.ipv4.conf.all.rp_filter is set to conflicting values as follows: #{unique_values}"
        incorrect_value_fail_message = "The net.ipv4.conf.all.rp_filter value is set to #{unique_values[0]} and should be set to #{rp_filter}"
        unless unique_values.empty?
          expect(unique_values.length).to cmp(1), conflicting_values_fail_message
          expect(unique_values[0]).to cmp(rp_filter), incorrect_value_fail_message
        end
      end
    end
    describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
      its('value') { should eq rp_filter }
    end
  end
end

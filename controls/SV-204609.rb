control 'SV-204609' do
  title 'The Red Hat Enterprise Linux operating system must not forward Internet Protocol version 4 (IPv4)
    source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a
    different path than configured on the router, which can be used to bypass network security measures. This
    requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the
    system is functioning as a router.'
  desc 'check', 'Verify the system does not accept IPv4 source-routed packets.

     # grep -r net.ipv4.conf.all.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
     net.ipv4.conf.all.accept_source_route = 0

If "net.ipv4.conf.all.accept_source_route" is not configured in the /etc/sysctl.conf file or in any of the other sysctl.d directories, is commented out, or does not have a value of "0", this is a finding.

Check that the operating system implements the accept source route variable with the following command:

     # /sbin/sysctl -a | grep net.ipv4.conf.all.accept_source_route
     net.ipv4.conf.all.accept_source_route = 0

If the returned line does not have a value of "0", this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Set the system to the required kernel parameter by adding the following
line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/
directory (or modify the line to have the required value):

    net.ipv4.conf.all.accept_source_route = 0

    Issue the following command to make the changes take effect:

    # sysctl -system'
  impact 0.5
  tag legacy: ['V-72283', 'SV-86907']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204609'
  tag rid: 'SV-204609r880797_rule'
  tag stig_id: 'RHEL-07-040610'
  tag fix_id: 'F-4733r880796_fix'
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
    accept_source_route = 0
    config_file_values = command('grep -r net.ipv4.conf.all.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null')
                         .stdout.strip.split("\n")
                         .map { |file| parse_config(file).params }
    config_file_values_uncompliant = config_file_values.select { |entry| entry.values != [accept_source_route.to_s] }

    unless config_file_values_uncompliant.empty?
      describe 'All configuration files' do
        it "should set accept_source_route to #{accept_source_route}, or not define it at all" do
          fail_msg = "Found incorrect configuration:\n#{config_file_values_uncompliant.join("\n")}"
          expect(config_file_values_uncompliant).to be_empty, fail_msg
        end
      end
    end

    describe 'The runtime kernel parameter net.ipv4.conf.all.accept_source_route' do
      subject { kernel_parameter('net.ipv4.conf.all.accept_source_route') }
      its('value') { should eq accept_source_route }
    end
  end
end

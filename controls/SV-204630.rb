control 'SV-204630' do
  title 'The Red Hat Enterprise Linux operating system must not forward IPv6 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a
    different path than configured on the router, which can be used to bypass network security measures. This
    requirement applies only to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled and the
    system is functioning as a router.'
  desc 'check', 'If IPv6 is not enabled, the key will not exist, and this is Not Applicable.

Verify the system does not accept IPv6 source-routed packets.

     # grep -r net.ipv6.conf.all.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
     net.ipv6.conf.all.accept_source_route = 0

If "net.ipv6.conf.all.accept_source_route" is not configured in the /etc/sysctl.conf file or in any of the other sysctl.d directories, is commented out or does not have a value of "0", this is a finding.

Check that the operating system implements the accept source route variable with the following command:

     # /sbin/sysctl -a | grep net.ipv6.conf.all.accept_source_route
     net.ipv6.conf.all.accept_source_route = 0

If the returned lines do not have a value of "0", this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Set the system to the required kernel parameter, if IPv6 is enabled, by
adding the following line to "/etc/sysctl.conf" or a configuration file in
the /etc/sysctl.d/ directory (or modify the line to have the required value):

    net.ipv6.conf.all.accept_source_route = 0

    Issue the following command to make the changes take effect:

    # sysctl --system'
  impact 0.5
  tag legacy: ['V-72319', 'SV-86943']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204630'
  tag rid: 'SV-204630r880827_rule'
  tag stig_id: 'RHEL-07-040830'
  tag fix_id: 'F-4754r880826_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['kernel_parameter', 'ipv6']
  tag 'host'
  tag 'container'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable - Kernel config must be done on the host' do
      skip 'Control not applicable - Kernel config must be done on the host'
    end
  else
    accept_source_route = 0
    config_file_values = command('grep -r net.ipv6.conf.all.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null')
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

    describe.one do
      describe kernel_parameter('net.ipv6.conf.all.accept_source_route') do
        its('value') { should eq accept_source_route }
      end
      # If IPv6 is disabled in the kernel it will return NIL
      describe kernel_parameter('net.ipv6.conf.all.accept_source_route') do
        its('value') { should eq nil }
      end
    end
  end
end

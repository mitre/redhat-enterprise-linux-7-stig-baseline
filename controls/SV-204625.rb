control 'SV-204625' do
  title 'The Red Hat Enterprise Linux operating system must not be performing packet forwarding unless the system is
    a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other
    routers. If this software is used when not required, system network information may be unnecessarily transmitted
    across the network.'
  desc 'check', 'Verify the system is not performing packet forwarding, unless the system is a router.

     # grep -r net.ipv4.ip_forward /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
     net.ipv4.ip_forward = 0

If "net.ipv4.ip_forward" is not configured in the /etc/sysctl.conf file or in any of the other sysctl.d directories, is commented out, or does not have a value of "0", this is a finding.

Check that the operating system does not implement IP forwarding using the following command:

     # /sbin/sysctl -a | grep net.ipv4.ip_forward
     net.ipv4.ip_forward = 0

If IP forwarding value is "1" and the system is hosting any application, database, or web servers, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Set the system to the required kernel parameter by adding the following
line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/
directory (or modify the line to have the required value):

    net.ipv4.ip_forward = 0

    Issue the following command to make the changes take effect:

    # sysctl --system'
  impact 0.5
  tag legacy: ['SV-86933', 'V-72309']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-204625'
  tag rid: 'SV-204625r880824_rule'
  tag stig_id: 'RHEL-07-040740'
  tag fix_id: 'F-4749r880823_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['kernel_parameter']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable - Kernel config must be done on the host' do
      skip 'Control not applicable - Kernel config must be done on the host'
    end
  else
    ip_forward = 0
    config_file_values = command('grep -r net.ipv4.ip_forward /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null').stdout.strip.split("\n")

    describe 'net.ipv4.ip_forward' do
      unless config_file_values.empty?
        config_file_values.each do |result|
          incorrect_value_fail_message = "Found value: #{parse_config(result).params.values[0]} in #{parse_config(result).params.keys[0]}"
          it "should be set to #{ip_forward}" do
            expect(parse_config(result).params.values[0].to_i).to eq(ip_forward), incorrect_value_fail_message
          end
        end
      end
    end

    describe 'The runtime kernel parameter net.ipv4.ip_forward' do
      subject { kernel_parameter('net.ipv4.ip_forward') }
      its('value') { should eq ip_forward }
    end
  end
end

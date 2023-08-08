control 'SV-204513' do
  title "The Red Hat Enterprise Linux operating system must initiate an action to notify the System Administrator
    (SA) and Information System Security Officer ISSO, at a minimum, when allocated audit record storage volume reaches
    #{input('storage_volume')}% of the repository maximum audit record storage capacity."
  desc "If security personnel are not notified immediately when storage volume reaches #{input('storage_volume')} percent utilization, they
  are unable to plan for audit record storage capacity expansion."
  desc 'check', "Verify the operating system initiates an action to notify the SA and ISSO (at a minimum) when
    allocated audit record storage volume reaches #{input('storage_volume')} percent of the repository maximum audit record storage capacity.
    Check the system configuration to determine the partition the audit records are being written to with the following
    command:
    $ sudo grep -iw log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log
    Determine what the threshold is for the system to take action when #{input('storage_volume')} percent of the repository maximum audit record
    storage capacity is reached:
    $ sudo grep -iw space_left /etc/audit/auditd.conf
    space_left = #{input('min_space_left')}%
    If the value of the \"space_left\" keyword is not set to #{input('min_space_left')} percent of the total partition size, this is a finding."
  desc 'fix', "Configure the operating system to initiate an action to notify the SA and ISSO (at a minimum) when
    allocated audit record storage volume reaches #{input('storage_volume')} percent of the repository maximum audit record storage capacity.
    Set the value of the \"space_left\" keyword in \"/etc/audit/auditd.conf\" to #{input('min_space_left')} percent of the partition size.
    space_left = #{input('min_space_left')}%
    Reload the auditd daemon to apply changes made to the \"/etc/audit/auditd.conf\" file."
  impact 0.5
  tag legacy: ['V-72089', 'SV-86713']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag gid: 'V-204513'
  tag rid: 'SV-204513r877389_rule'
  tag stig_id: 'RHEL-07-030330'
  tag fix_id: 'F-4637r744111_fix'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
  tag subsystems: ['audit', 'auditd']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable - audit config must be done on the host' do
      skip 'Control not applicable - audit config must be done on the host'
    end
  else
    describe auditd_conf do
      its('space_left') { should cmp >= input('min_space_left') }
    end
  end
end

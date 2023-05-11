control 'SV-204446' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that designated personnel are notified
    if baseline configurations are changed in an unauthorized manner.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information System Security Manager (ISSM)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', 'Verify the operating system notifies designated personnel if baseline configurations are changed in an unauthorized manner.

Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed and notify specified individuals via email or an alert.

Check for the presence of a cron job running routinely on the system that executes AIDE to scan for changes to the system baseline. The commands used in the example will use a daily occurrence.

Check the cron directories for a "crontab" script file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:

     # ls -al /etc/cron.* | grep aide
     -rwxr-xr-x 1 root root 602 Mar 6 20:02 aide

     # grep aide /etc/crontab /var/spool/cron/root
     /etc/crontab: 30 04 * * * root /usr/sbin/aide  --check
     /var/spool/cron/root: 30 04 * * * /usr/sbin/aide  --check

AIDE does not have a configuration that will send a notification, so the cron job uses the mail application on the system to email the results of the file integrity run as in the following example:

     # more /etc/cron.daily/aide
     #!/bin/bash

     /usr/sbin/aide --check | /var/spool/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil

If the file integrity application does not notify designated personnel of changes, this is a finding.'
  desc 'fix', 'Configure the operating system to notify designated personnel if baseline configurations are changed in an unauthorized manner. The AIDE tool can be configured to email designated personnel with the use of the cron system.

The following example output is generic. It will set cron to run AIDE daily and to send email at the completion of the analysis.

     # more /etc/cron.daily/aide

     /usr/sbin/aide --check | /var/spool/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil'
  impact 0.5
  tag legacy: ['V-71975', 'SV-86599']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag gid: 'V-204446'
  tag rid: 'SV-204446r880851_rule'
  tag stig_id: 'RHEL-07-020040'
  tag fix_id: 'F-36305r880850_fix'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
  tag subsystems: ['file_integrity_tool']
  tag 'host'
  tag 'container'

  file_integrity_tool = input('file_integrity_tool')

  describe.one do
    describe file("/etc/cron.daily/#{file_integrity_tool}") do
      its('content') { should match %r{/var/spool/mail} }
    end
    describe file("/etc/cron.weekly/#{file_integrity_tool}") do
      its('content') { should match %r{/var/spool/mail} }
    end
    describe crontab('root').where {
               command =~ /#{file_integrity_tool}/
             } do
      its('commands.flatten') { should include(match %r{/var/spool/mail}) }
    end
    if file("/etc/cron.d/#{file_integrity_tool}").exist?
      describe crontab(path: "/etc/cron.d/#{file_integrity_tool}") do
        its('commands') { should include(match %r{/var/spool/mail}) }
      end
    end
  end
end

control 'SV-204445' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that a file integrity tool verifies the
    baseline operating system configuration at least weekly.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information System Security Manager (ISSM)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', 'Verify the operating system routinely checks the baseline configuration for unauthorized changes.

Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed at least once per week.

Check for the presence of a cron job running daily or weekly on the system that executes AIDE daily to scan for changes to the system baseline. The command used in the example will use a daily occurrence.

Check the cron directories for a script file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:

     # ls -al /etc/cron.* | grep aide
     -rwxr-xr-x 1 root root 602 Mar 6 20:02 aide

     # grep aide /etc/crontab /var/spool/cron/root
     /etc/crontab: 30 04 * * * root /usr/sbin/aide  --check
     /var/spool/cron/root: 30 04 * * * /usr/sbin/aide  --check

If the file integrity application does not exist, or a script file controlling the execution of the file integrity application does not exist, this is a finding.'
  desc 'fix', 'Configure the file integrity tool to run automatically on the system at least weekly. The following example output is generic. It will set cron to run AIDE daily, but other file integrity tools may be used:

     # more /etc/cron.daily/aide
     #!/bin/bash

     /usr/sbin/aide --check | /var/spool/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil'
  impact 0.5
  tag legacy: ['SV-86597', 'V-71973']
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag gid: 'V-204445'
  tag rid: 'SV-204445r880848_rule'
  tag stig_id: 'RHEL-07-020030'
  tag fix_id: 'F-36304r880847_fix'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
  tag subsystems: ['file_integrity_tool']
  tag 'host'
  tag 'container'

  file_integrity_tool = input('file_integrity_tool')
  file_integrity_interval = input('file_integrity_interval')

  if file_integrity_tool == 'aide'
    if file_integrity_interval == 'monthly'
      describe.one do
        describe file("/etc/cron.daily/#{file_integrity_tool}") do
          it { should exist }
        end
        describe file("/etc/cron.weekly/#{file_integrity_tool}") do
          it { should exist }
        end
        describe file("/etc/cron.monthly/#{file_integrity_tool}") do
          it { should exist }
        end
        if file("/etc/cron.d/#{file_integrity_tool}").exist?
          describe crontab(path: "/etc/cron.d/#{file_integrity_tool}") do
            its('months') { should cmp '*' }
            its('weekdays') { should cmp '*' }
          end
          describe crontab(path: "/etc/cron.d/#{file_integrity_tool}") do
            its('days') { should cmp '*' }
            its('months') { should cmp '*' }
          end
        end
        describe crontab('root').where {
                  command =~ /#{file_integrity_tool}/
                }                do
          its('months') { should cmp '*' }
          its('weekdays') { should cmp '*' }
        end
        describe crontab('root').where {
                  command =~ /#{file_integrity_tool}/
                }                do
          its('days') { should cmp '*' }
          its('months') { should cmp '*' }
        end
      end
    elsif file_integrity_interval == 'weekly'
      describe.one do
        describe file("/etc/cron.daily/#{file_integrity_tool}") do
          it { should exist }
        end
        describe file("/etc/cron.weekly/#{file_integrity_tool}") do
          it { should exist }
        end
        if file("/etc/cron.d/#{file_integrity_tool}").exist?
          describe crontab(path: "/etc/cron.d/#{file_integrity_tool}") do
            its('days') { should cmp '*' }
            its('months') { should cmp '*' }
          end
        end
        describe crontab('root').where {
                  command =~ /#{file_integrity_tool}/
                }                do
          its('days') { should cmp '*' }
          its('months') { should cmp '*' }
        end
      end
    elsif file_integrity_interval == 'daily'
      describe.one do
        describe file("/etc/cron.daily/#{file_integrity_tool}") do
          it { should exist }
        end
        if file("/etc/cron.d/#{file_integrity_tool}").exist?
          describe crontab(path: "/etc/cron.d/#{file_integrity_tool}") do
            its('days') { should cmp '*' }
            its('months') { should cmp '*' }
            its('weekdays') { should cmp '*' }
          end
        end
        describe crontab('root').where {
                  command =~ /#{file_integrity_tool}/
                }                do
          its('days') { should cmp '*' }
          its('months') { should cmp '*' }
          its('weekdays') { should cmp '*' }
        end
      end
    end
  else
    describe 'Need manual review of file integrity tool' do
      skip 'A manual review of the file integrity tool is required to ensure that it verifies the baseline operating system configuration at least weekly.'
    end
  end
end

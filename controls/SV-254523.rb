control 'SV-254523' do
  title 'The Red Hat Enterprise Linux operating system must automatically expire temporary accounts within 72 hours.'
  desc 'Temporary accounts are privileged or nonprivileged accounts that are established during pressing circumstances, such as new software or hardware configuration or an incident response, where the need for prompt account activation requires bypassing normal account authorization procedures. If any inactive temporary accounts are left enabled on the system and are not either manually removed or automatically expired within 72 hours, the security posture of the system will be degraded and exposed to exploitation by unauthorized users or insider threat actors.

Temporary accounts are different from emergency accounts. Emergency accounts, also known as "last resort" or "break glass" accounts, are local logon accounts enabled on the system for emergency use by authorized system administrators to manage a system when standard logon methods are failing or not available. Emergency accounts are not subject to manual removal or scheduled expiration requirements.

The automatic expiration of temporary accounts may be extended as needed by the circumstances but it must not be extended indefinitely. A documented permanent account should be established for privileged users who need long-term maintenance accounts.'
  desc 'check', 'Verify temporary accounts have been provisioned with an expiration date of 72 hours.

For every existing temporary account, run the following command to obtain its account expiration information:

     $ sudo chage -l <temporary_account_name> | grep -i "account expires"

Verify each of these accounts has an expiration date set within 72 hours.
If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.'
  desc 'fix', 'Configure the operating system to expire temporary accounts after 72 hours with the following command:

     $ sudo chage -E $(date -d +3days +%Y-%m-%d) <temporary_account_name>'
  impact 0.5
  tag check_id: 'C-58007r902691_chk'
  tag severity: 'medium'
  tag gid: 'V-254523'
  tag rid: 'SV-254523r903130_rule'
  tag stig_id: 'RHEL-07-010271'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-57956r902692_fix'
  tag documentable: nil
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']

  emergency_accounts = input('emergency_accounts')

  if emergency_accounts.empty?
    describe 'Emergency accounts' do
      subject { emergency_accounts }
      it { should be_empty }
    end
  else
    emergency_accounts.each do |acct|
      describe user(acct.to_s) do
        its('maxdays') { should cmp <= 3 }
        its('maxdays') { should cmp > 0 }
      end
    end
  end
end

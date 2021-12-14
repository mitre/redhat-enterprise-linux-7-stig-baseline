# encoding: UTF-8

control 'SV-204426' do
  title "The Red Hat Enterprise Linux operating system must disable account
identifiers (individuals, groups, roles, and devices) if the password expires."
  desc  "Inactive identifiers pose a risk to systems and applications because
attackers may exploit an inactive identifier and potentially obtain undetected
access to the system. Owners of inactive accounts will not notice if
unauthorized access to their user account has been obtained.

    Operating systems need to track periods of inactivity and disable
application identifiers after zero days of inactivity.
  "
  desc  'rationale', ''
  desc  'check', "
    If passwords are not being used for authentication, this is Not Applicable.

    Verify the operating system disables account identifiers (individuals,
groups, roles, and devices) after the password expires with the following
command:

    # grep -i inactive /etc/default/useradd
    INACTIVE=0

    If the value is not set to \"0\", is commented out, or is not defined, this
is a finding.
  "
  desc  'fix', "
    Configure the operating system to disable account identifiers (individuals,
groups, roles, and devices) after the password expires.

    Add the following line to \"/etc/default/useradd\" (or modify the line to
have the required value):

    INACTIVE=0
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag gid: 'V-204426'
  tag rid: 'SV-204426r603261_rule'
  tag stig_id: 'RHEL-07-010310'
  tag fix_id: 'F-4550r88471_fix'
  tag cci: ['CCI-000795']
  tag legacy: ['SV-86565', 'V-71941']
  tag nist: ['IA-4 e']
end


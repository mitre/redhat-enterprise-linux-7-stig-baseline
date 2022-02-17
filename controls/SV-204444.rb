# encoding: UTF-8

control 'SV-204444' do
  title "The Red Hat Enterprise Linux operating system must prevent
non-privileged users from executing privileged functions to include disabling,
circumventing, or altering implemented security safeguards/countermeasures."
  desc  "Preventing non-privileged users from executing privileged functions
mitigates the risk that unauthorized individuals or processes may gain
unnecessary access to information or privileges.

    Privileged functions include, for example, establishing accounts,
performing system integrity checks, or administering cryptographic key
management activities. Non-privileged users are individuals who do not possess
appropriate authorizations. Circumventing intrusion detection and prevention
mechanisms or malicious code protection mechanisms are examples of privileged
functions that require protection from non-privileged users.
  "
  desc  'rationale', ''
  desc  'check', "
    Note: Per OPORD 16-0080, the preferred endpoint security tool is Endpoint
Security for Linux (ENSL) in conjunction with SELinux.

    Verify the operating system prevents non-privileged users from executing
privileged functions to include disabling, circumventing, or altering
implemented security safeguards/countermeasures.

    Get a list of authorized users for the system.

    Check the list against the system by using the following command:

    $ sudo semanage login -l | more

    Login Name SELinux User MLS/MCS Range Service
    __default__ user_u s0-s0:c0.c1023 *
    root unconfined_u s0-s0:c0.c1023 *
    system_u system_u s0-s0:c0.c1023 *
    joe staff_u s0-s0:c0.c1023 *

    All administrators must be mapped to the , \"staff_u\", or an appropriately
tailored confined SELinux user as defined by the organization.

    All authorized non-administrative users must be mapped to the \"user_u\"
SELinux user.

    If they are not mapped in this way, this is a finding.
    If administrator accounts are mapped to the \"sysadm_u\" SELinux user and
are not documented as an operational requirement with the ISSO, this is a
finding.
    If administrator accounts are mapped to the \"sysadm_u\" SELinux user and
are documented as an operational requirement with the ISSO, this can be
downgraded to a CAT III.
  "
  desc  'fix', "
    Configure the operating system to prevent non-privileged users from
executing privileged functions to include disabling, circumventing, or altering
implemented security safeguards/countermeasures.

    Use the following command to map a new user to the \"staff_u\" SELinux user:

    $ sudo semanage login -a -s staff_u <username>

    Use the following command to map an existing user to the \"staff_u\"
SELinux user:

    $ sudo semanage login -m -s staff_u <username>

    Use the following command to map a new user to the \"user_u\" SELinux user:

    $ sudo semanage login -a -s user_u <username>

    Use the following command to map an existing user to the \"user_u\" SELinux
user:

    $ sudo semanage login -m -s user_u <username>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag gid: 'V-204444'
  tag rid: 'SV-204444r792826_rule'
  tag stig_id: 'RHEL-07-020020'
  tag fix_id: 'F-4568r792825_fix'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag legacy: ['SV-86595', 'V-71971']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
end


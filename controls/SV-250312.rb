# encoding: UTF-8

control 'SV-250312' do
  title "The Red Hat Enterprise Linux operating system must confine SELinux
users to roles that conform to least privilege."
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

    Verify the operating system confines SELinux users to roles that conform to
least privilege.

    Check the SELinux User list to SELinux Roles mapping by using the following
command:

    $ sudo semanage user -l
    SELinuxUser LabelingPrefix MLS/MCSLevel MLS/MCSRange SELinuxRoles
    guest_u            user  s0  s0  guest_r
    root                   user  s0  s0-s0:c0.c1023  staff_r sysadm_r system_r
unconfined_r
    staff_u              user  s0  s0-s0:c0.c1023  staff_r sysadm_r
    sysadm_u         user  s0  s0-s0:c0.c1023  sysadm_r
    system_u          user  s0  s0-s0:c0.c1023  system_r unconfined_r
    unconfined_u  user  s0  s0-s0:c0.c1023  system_r unconfined_r
    user_u               user  s0  s0  user_r
    xguest_u           user  s0  s0  xguest_r

    If the output differs from the above example, ask the SA to demonstrate how
the SELinux User mappings are exercising least privilege. If deviations from
the example are not documented with the ISSO and do not demonstrate least
privilege, this is a finding.
  "
  desc  'fix', "
    Configure the operating system to confine SELinux users to roles that
conform to least privilege.

    Use the following command to map the \"staff_u\" SELinux user to the
\"staff_r\" and \"sysadm_r\" roles:

    $ sudo semanage user -m staff_u -R staff_r -R sysadm_r

    Use the following command to map the \"user_u\" SELinux user to the
\"user_r\" role:

    $ sudo semanage -m user_u -R user_r
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag gid: 'V-250312'
  tag rid: 'SV-250312r792843_rule'
  tag stig_id: 'RHEL-07-020021'
  tag fix_id: 'F-53700r792842_fix'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
end


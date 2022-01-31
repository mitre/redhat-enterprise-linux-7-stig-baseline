# -*- encoding : utf-8 -*-
control "V-72165" do
  title "The Red Hat Enterprise Linux operating system must audit all uses of
the newgrp command."
  desc  "Reconstruction of harmful events or forensic analysis is not possible
if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged access commands. The organization must maintain audit trails in
sufficient detail to reconstruct events to determine the cause and impact of
compromise.


  "
  tag 'rationale': ""
  tag 'check': "
    Verify the operating system generates audit records when
successful/unsuccessful attempts to use the \"newgrp\" command occur.

    Check that the following system call is being audited by performing the
following command to check the file system rules in \"/etc/audit/audit.rules\":

    # grep -i /usr/bin/newgrp /etc/audit/audit.rules

    -a always,exit -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=4294967295 -k
privileged-priv_change

    If the command does not return any output, this is a finding.
  "
  tag 'fix': "
    Configure the operating system to generate audit records when
successful/unsuccessful attempts to use the \"newgrp\" command occur.

    Add or update the following rule in \"/etc/audit/rules.d/audit.rules\":

    -a always,exit -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=4294967295 -k
privileged-priv_change

    The audit daemon must be restarted for the changes to take effect.
  "
  tag severity: nil
  tag gtitle: "SRG-OS-000037-GPOS-00015"
  tag satisfies: ["SRG-OS-000037-GPOS-00015", "SRG-OS-000042-GPOS-00020",
"SRG-OS-000392-GPOS-00172", "SRG-OS-000462-GPOS-00206",
"SRG-OS-000471-GPOS-00215"]
  tag gid: "V-72165"
  tag rid: "SV-86789r4_rule"
  tag stig_id: "RHEL-07-030710"
  tag fix_id: "F-78519r5_fix"
  tag cci: ["CCI-000130", "CCI-000135", "CCI-000172", "CCI-002884"]
  tag nist: ["AU-3", "AU-3 (1)", "AU-12 c", "MA-4 (1) (a)"]

  audit_file = '/usr/bin/newgrp'

  if file(audit_file).exist?
    impact 0.5
  else
    impact 0.0
  end

  describe auditd.file(audit_file) do
    its('permissions') { should include ['x'] }
    its('action') { should_not include 'never' }
  end if file(audit_file).exist?

  describe "The #{audit_file} file does not exist" do
    skip "The #{audit_file} file does not exist, this requirement is Not Applicable."
  end if !file(audit_file).exist?
end

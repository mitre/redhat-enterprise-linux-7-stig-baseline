# encoding: UTF-8

control 'SV-214799' do
  title "The Red Hat Enterprise Linux operating system must be configured so
that the cryptographic hash of system files and commands matches vendor values."
  desc  "Without cryptographic integrity protections, system command and files
can be altered by unauthorized users without detection.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the key used to generate the hash.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the cryptographic hash of system files and commands match the vendor
values.

    Check the cryptographic hash of system files and commands with the
following command:

    Note: System configuration files (indicated by a \"c\" in the second
column) are expected to change over time. Unusual modifications should be
investigated through the system audit log.

    # rpm -Va --noconfig | grep '^..5'

    If there is any output from the command for system files or binaries, this
is a finding.
  "
  desc  'fix', "
    Run the following command to determine which package owns the file:

    # rpm -qf <filename>

    The package can be reinstalled from a yum repository using the command:

    # sudo yum reinstall <packagename>

    Alternatively, the package can be reinstalled from trusted media using the
command:

    # sudo rpm -Uvh <packagename>
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-214799'
  tag rid: 'SV-214799r603261_rule'
  tag stig_id: 'RHEL-07-010020'
  tag fix_id: 'F-15997r192363_fix'
  tag cci: ['CCI-001749']
  tag legacy: ['SV-86479', 'V-71855']
  tag nist: ['CM-5 (3)']
end


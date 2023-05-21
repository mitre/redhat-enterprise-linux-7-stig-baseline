require 'shellwords'

control 'SV-204392' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the file permissions, ownership,
    and group membership of system files and commands match the vendor values.'
  desc 'Discretionary access control is weakened if a user or group has access permissions to system files and
    directories greater than the default.'
  desc 'check', %q(Verify the file permissions, ownership, and group membership of system files and commands match the vendor values.

Check the default file permissions, ownership, and group membership of system files and commands with the following command:

     # for i in `rpm -Va | grep -E '^.{1}M|^.{5}U|^.{6}G' | cut -d " " -f 4,5`;do for j in `rpm -qf $i`;do rpm -ql $j --dump | cut -d " " -f 1,5,6,7 | grep $i;done;done

     /var/log/gdm 040755 root root
     /etc/audisp/audisp-remote.conf 0100640 root root
     /usr/bin/passwd 0104755 root root

For each file returned, verify the current permissions, ownership, and group membership:
     # ls -la <filename>

     -rw-------. 1 root root 2017 Nov 1 10:03 /etc/audisp/audisp-remote.conf

If the file is more permissive than the default permissions, this is a finding.

If the file is not owned by the default owner and is not documented with the Information System Security Officer (ISSO), this is a finding.

If the file is not a member of the default group and is not documented with the Information System Security Officer (ISSO), this is a finding.)
  desc 'fix', 'Run the following command to determine which package owns the file:

    # rpm -qf <filename>

    Reset the user and group ownership of files within a package with the
following command:

    #rpm --setugids <packagename>


    Reset the permissions of files within a package with the following command:

    #rpm --setperms <packagename>'
  impact 0.7
  tag legacy: ['V-71849', 'SV-86473']
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag satisfies: ['SRG-OS-000257-GPOS-00098', 'SRG-OS-000278-GPOS-00108']
  tag gid: 'V-204392'
  tag rid: 'SV-204392r880752_rule'
  tag stig_id: 'RHEL-07-010010'
  tag fix_id: 'F-36302r880751_fix'
  tag cci: ['CCI-001494', 'CCI-001496', 'CCI-002165', 'CCI-002235']
  tag nist: ['AU-9', 'AU-9 (3)', 'AC-3 (4)', 'AC-6 (10)']
  tag subsystems: ['permissions', 'package', 'rpm']
  tag 'host'
  tag 'container'

  if input('disable_slow_controls')
    describe "This control consistently takes a long time to run and has been disabled
    using the disable_slow_controls attribute." do
      skip "This control consistently takes a long time to run and has been disabled
            using the disable_slow_controls attribute. You must enable this control for a
            full accredidation for production."
    end
  else
    ownership_allowlist = input('rpm_verify_ownership_except')
    pp "ownership allowlist", ownership_allowlist
    group_membership_allowlist = input('rpm_verify_group_membership_except')
    pp "group membership allowlist", group_membership_allowlist

    identified_files = command('rpm -Va | awk \'/^.{1}M|^.{5}U|^.{6}G/ {print $NF}\'').stdout.split("\n")
    pp "identified files", identified_files

    if identified_files.empty?
      describe 'The list of system files and commands with permissions, ownership, or group membership changed from the vendor values' do
        subject { identified_files }
        it { should be_empty }
      end
    else
      misconfigured_packages = identified_files.flat_map { |f| command("rpm -qf #{f}").stdout.split("\n") }.uniq
      pp "misconfigured packages", misconfigured_packages
      potentially_misconfigured_files = misconfigured_packages.flat_map { |p| command("rpm -ql #{p} --dump").stdout.split("\n") }.uniq.map(&:shellsplit)
      pp "all files", potentially_misconfigured_files
      potentially_misconfigured_files.each do |path, size, mtime, digest, mode, owner, group, isconfig, isdoc, rdev, symlink|
        pp "package info:", path, size, mtime, digest, mode, owner, group, isconfig, isdoc, rdev, symlink
        file_obj = file(path)
        describe file_obj do
          pp "file info:", file_obj.path, file_obj.exist?, file_obj.mode, file_obj.owner, file_obj.group
          it { should_not be_more_permissive_than(mode) }
          if ownership_allowlist.include? path
            it { should be_owned_by owner }
          end
          if group_membership_allowlist.include? path
            it { should be_grouped_into group }
          end
        end
        pp "created control"
      end
      pp "created all describes"
    end
    pp "finished if/else for identified files being empty"
  end
  pp "finished if/else for disabled slow controls"
end

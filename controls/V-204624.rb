control 'V-204624' do
  title 'The Red Hat Enterprise Linux operating system must not have a graphical display manager installed unless
    approved.'
  desc 'Internet services that are not required for system or application processes must not be active to decrease
    the attack surface of the system. Graphical display managers have a long history of security vulnerabilities and
    must not be used unless approved and documented.'
  desc  'rationale', ''
  desc  'check',
    "
    Verify that if the system has X Windows System installed, it is authorized.

    Check for the X11 package with the following command:

    # rpm -qa | grep xorg | grep server

    Ask the System Administrator if use of the X Windows System is an
operational requirement.

    If the use of X Windows on the system is not documented with the
Information System Security Officer (ISSO), this is a finding.
  "
  desc 'fix',
    "
    Document the requirement for an X Windows server with the ISSO or remove
the related packages with the following commands:

    # rpm -e xorg-x11-server-common
  "
  impact 0.5
  tag 'severity': 'medium'
  tag 'gtitle': 'SRG-OS-000480-GPOS-00227'
  tag 'gid': 'V-204624'
  tag 'legacy_id': 'V-72307'
  tag 'rid': 'SV-204624r646847_rule'
  tag 'stig_id': 'RHEL-07-040730'
  tag 'fix_id': 'F-36316r646846_fix'
  tag 'cci': ['CCI-000366']
  tag 'nist': ['CM-6 b']

  x11_enabled = input('x11_enabled')

  unless x11_enabled
    describe package('xorg-x11-server-common') do
      it { should_not be_installed }
    end
  end

  if x11_enabled
    describe package('xorg-x11-server-common') do
      it { should be_installed }
    end
  end
end

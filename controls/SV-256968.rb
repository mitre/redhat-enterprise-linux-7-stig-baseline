control 'SV-256968' do
  title 'The Red Hat Enterprise Linux operating system must ensure cryptographic verification of vendor software packages.'
  desc 'Cryptographic verification of vendor software packages ensures that all software packages are obtained from a valid source and protects against spoofing that could lead to installation of malware on the system. Red Hat cryptographically signs all software packages, which includes updates, with a GPG key to verify that they are valid.'
  desc 'check', 'Confirm Red Hat package-signing keys are installed on the system and verify their fingerprints match vendor values.

Note: For Red Hat Enterprise Linux 7 software packages, Red Hat uses GPG keys labeled "release key 2" and "auxiliary key". The keys are defined in key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release" by default.

List Red Hat GPG keys installed on the system:

     $ sudo rpm -q --queryformat "%{SUMMARY}\\n" gpg-pubkey | grep -i "red hat"

     gpg(Red Hat, Inc. (release key 2) <security@redhat.com>)
     gpg(Red Hat, Inc. (auxiliary key) <security@redhat.com>)

If Red Hat GPG keys "release key 2" and "auxiliary key" are not installed, this is a finding.

List key fingerprints of installed Red Hat GPG keys:

     $ sudo gpg -q --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

If key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release" is missing, this is a finding.

Example output:

     pub  4096R/FD431D51 2009-10-22 Red Hat, Inc. (release key 2) <security@redhat.com>
           Key fingerprint = 567E 347A D004 4ADE 55BA  8A5F 199E 2F91 FD43 1D51
     pub  1024D/2FA658E0 2006-12-01 Red Hat, Inc. (auxiliary key) <security@redhat.com>
           Key fingerprint = 43A6 E49C 4A38 F4BE 9ABF  2A53 4568 9C88 2FA6 58E0
	   
Compare key fingerprints of installed Red Hat GPG keys with fingerprints listed on Red Hat "Product Signing Keys" webpage at https://access.redhat.com/security/team/key.

If key fingerprints do not match, this is a finding.'
  desc 'fix', 'Install Red Hat package-signing keys on the system and verify their fingerprints match vendor values.

Insert RHEL 7 installation disc or attach RHEL 7 installation image to the system. Mount the disc or image to make the contents accessible inside the system.

Assuming the mounted location is "/media/cdrom", use the following command to copy Red Hat GPG key file onto the system:

     $ sudo cp /media/cdrom/RPM-GPG-KEY-redhat-release /etc/pki/rpm-gpg/
	 
Import Red Hat GPG keys from key file into system keyring:

     $ sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
	 
Using the steps listed in the Check Text, confirm the newly imported keys show as installed on the system and verify their fingerprints match vendor values.'
  impact 0.5
  tag check_id: 'C-60646r902685_chk'
  tag severity: 'medium'
  tag gid: 'V-256968'
  tag rid: 'SV-256968r902687_rule'
  tag stig_id: 'RHEL-07-010019'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-60588r902686_fix'
  tag documentable: nil
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

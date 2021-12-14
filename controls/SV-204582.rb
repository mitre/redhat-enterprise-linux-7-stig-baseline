# encoding: UTF-8

control 'SV-204582' do
  title "The Red Hat Enterprise Linux operating system must implement
cryptography to protect the integrity of Lightweight Directory Access Protocol
(LDAP) communications."
  desc  "Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the key used to generate the hash.
  "
  desc  'rationale', ''
  desc  'check', "
    If LDAP is not being utilized, this requirement is Not Applicable.

    Verify the operating system implements cryptography to protect the
integrity of remote LDAP access sessions.

    To determine if LDAP is being used for authentication, use the following
command:

    # systemctl status sssd.service
    sssd.service - System Security Services Daemon
    Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled; vendor
preset: disabled)
    Active: active (running) since Wed 2018-06-27 10:58:11 EST; 1h 50min ago

    If the \"sssd.service\" is \"active\", then LDAP is being used.

    Determine the \"id_provider\" the LDAP is currently using:

    # grep -i \"id_provider\" /etc/sssd/sssd.conf

    id_provider = ad

    If \"id_provider\" is set to \"ad\", this is Not Applicable.

    Verify the sssd service is configured to require the use of certificates:

    # grep -i tls_reqcert /etc/sssd/sssd.conf
    ldap_tls_reqcert = demand

    If the \"ldap_tls_reqcert\" setting is missing, commented out, or does not
exist, this is a finding.

    If the \"ldap_tls_reqcert\" setting is not set to \"demand\" or \"hard\",
this is a finding.
  "
  desc  'fix', "
    Configure the operating system to implement cryptography to protect the
integrity of LDAP remote access sessions.

    Add or modify the following line in \"/etc/sssd/sssd.conf\":

    ldap_tls_reqcert = demand
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag gid: 'V-204582'
  tag rid: 'SV-204582r603261_rule'
  tag stig_id: 'RHEL-07-040190'
  tag fix_id: 'F-4706r88939_fix'
  tag cci: ['CCI-001453']
  tag legacy: ['V-72229', 'SV-86853']
  tag nist: ['AC-17 (2)']
end


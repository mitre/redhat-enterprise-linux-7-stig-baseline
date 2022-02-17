# RHEL7 STIG Automated Compliance Validation Profile

<b>RHEL 7.X</b> STIG Automated Compliance Validation Profile works with Chef InSpec to perform automated compliance checks of <b>RHEL7</b>.

This automated Security Technical Implementation Guide (STIG) validator was developed to reduce the time it takes to perform a security check based upon STIG Guidance from DISA. These check results should provide information needed to receive a secure authority to operate (ATO) certification for the applicable technology.
<b>RHEL7</b> uses [Chef InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.

## RHEL7 STIG Overview

The <b>RHEL7</b> STIG (https://public.cyber.mil/stigs/) by the United States Defense Information Systems Agency (DISA) offers a comprehensive compliance guide for the configuration and operation of various technologies.
DISA has created and maintains a set of security guidelines for applications, computer systems or networks connected to the DoD. These guidelines are the primary security standards used by many DoD agencies. In addition to defining security guidelines, the STIG also stipulates how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

[STIG](https://en.wikipedia.org/wiki/Security_Technical_Implementation_Guide)s are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA). Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the STIGs. The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

The requirements associated with the <b>RHEL8</b> STIG are derived from the [National Institute of Standards and Technology](https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology) (NIST) [Special Publication (SP) 800-53, Revision 4](https://en.wikipedia.org/wiki/NIST_Special_Publication_800-53) and related documents.

While the RHEL8 STIG automation profile check was developed to provide technical guidance to validate information with security systems such as applications, the guidance applies to all organizations that need to meet internal security as well as compliance standards.

### This STIG Automated Compliance Validation Profile was developed based upon:

- RHEL8 Security Technical Implementation Guide

### Update History

| Guidance Name                             | Guidance Version | Guidance Location                         | Profile Version | Profile Release Date | STIG EOL | Profile EOL |
| ----------------------------------------- | ---------------- | ----------------------------------------- | --------------- | -------------------- | -------- | ----------- |
| Red Hat Enterprise Linux 7 STIG Benchmark | v3r5             | https://public.cyber.mil/stigs/downloads/ | 1.0.0           | NA                   | NA       | NA          |

## Getting Started

### Requirements

#### RHEL7

- Local or remote access to the RHEL7 Operating System
- Account providing appropriate permissions to perform audit scan

#### Required software on RHEL7 OS

- git
- [InSpec](https://www.chef.io/products/chef-inspec/)

### Setup Environment on RHEL7 OS

#### Install InSpec

Goto https://www.inspec.io/downloads/ and consult the documentation for your Operating System to download and install InSpec.

#### Ensure InSpec version is at least 4.23.10

```sh
inspec --version
```

### Update Profile Input Values

Check the `Inputs` in `inspec.yml` to determine if the default values differ in your platform.

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)

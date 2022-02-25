# RHEL8 STIG Automated Compliance Validation Profile

<b>RHEL 7.X</b> STIG Automated Compliance Validation Profile works with Chef InSpec to perform automated compliance checks of the RHEL7 operating system.

This automated Security Technical Implementation Guide (STIG) validator was developed to reduce the time it takes to perform a security check based upon STIG Guidance from DISA. These check results should provide information needed to receive a secure authority to operate (ATO) certification for the applicable technology.
<b>RHEL7</b> uses [Chef InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.

<b>**Please note: **</b> This InSpec Profile can assess RHEL7 installations which are hosts (such as bare-metal OS installations and VM installations) and RHEL7 containers. Running this profile against a RHEL7 container will skip the control checks which are not relevant to containers (such as controls dealing with the GUI). For the purposes of developing this profile, Red Hat's [Universal Base Image 7 (UBI7)](https://catalog.redhat.com/software/container-stacks/detail/5eed413846bc301a95a1e9a1) was used as the representative test target for containerized RHEL7.

See the section for the Control Overview to see which controls are container-applicable.

## RHEL7 STIG Overview

[STIG](https://public.cyber.mil/stigs/)s are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA). Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the STIGs. The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

The requirements associated with the <b>RHEL7</b> STIG are derived from the [National Institute of Standards and Technology](https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology) (NIST) [Special Publication (SP) 800-53, Revision 4](https://en.wikipedia.org/wiki/NIST_Special_Publication_800-53) and related documents.

While the RHEL7 STIG automation profile check was developed to provide technical guidance to validate information with security systems such as applications, the guidance applies to all organizations that need to meet internal security as well as compliance standards.

### This STIG Automated Compliance Validation Profile was developed based upon:

- RHEL7 Security Technical Implementation Guide (available from [DISA's STIGs Document Library](https://public.cyber.mil/stigs/downloads/))

### Update History

| Guidance Name                             | Guidance Version | Guidance Location                         | Profile Version | Profile Release Date | STIG EOL | Profile EOL |
| ----------------------------------------- | ---------------- | ----------------------------------------- | --------------- | -------------------- | -------- | ----------- |
| Red Hat Enterprise Linux 7 STIG Benchmark | v3r6             | https://public.cyber.mil/stigs/downloads/ | 3.6.0           | 02/25/2022           | NA       | NA          |

## Getting Started

### Requirements

#### RHEL7

- Local or remote access to the RHEL7 Operating System (SSH)
- Account providing appropriate permissions to perform audit scan (sudo privileges)

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

Update the following `Inputs` in `inspec.yml` if the default values differ in your platform.

```yml

```

### How to execute this instance

(See: https://www.inspec.io/docs/reference/cli/)

#### Execute a single control in the profile

**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.

```sh
inspec exec <Profile> -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --controls=<control_id> --show-progress
```

#### Execute a single control when password is required for privilege escalation

```
inspec exec <Profile> -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo --sudo-password=$SUDO_PASSWORD -i <your_PEM_KEY> --controls=<control_id> --show-progress
```

#### Execute a single control and save results as JSON

```sh
inspec exec <Profile> -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --controls=<control_id> --show-progress --reporter json:results.json
```

#### Execute all controls in the profile

```sh
inspec exec <Profile>  -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --show-progress
```

#### Execute all the controls in the profile and save results as JSON

```sh
inspec exec <Profile> -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --show-progress  --reporter json:results.json
```

#### Execute the profile against a Docker container

```sh
inspec exec <Profile>  -t docker://<container id> --sudo --show-progress
```

## Control Overview

The following table lists the controls in the RHEL7 STIG, which this profile implements in code. Not all controls are relevant to a containerized version of RHEL7. Those that are not applicable to containers have been marked.

| Control ID | Title | Container Applicable? | Rationale |

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Feedback and Support

For questions or comments regarding the validation profile, please contact the DISA SD DevSecOps Helpdesk: disa.meade.sd.mbx.devsecops-mailbox@mail.mil

## Legal Notices

Copyright © 2022 Defense Information Systems Agency (DISA)

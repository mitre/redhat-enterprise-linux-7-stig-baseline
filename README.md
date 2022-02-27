# RedHat 7.x Enterprise Linux Security Technical Implementation Guide (RHEL7.x STIG) InSpec Profile

[[_TOC_]]

The <b>Redhat Enterprise Linux 7.X</b> Security Technical Implementation Guide (RHEL7.x STIG) InSpec Profile will help you automate your compliance checks of <b>RedHat Enterprise Linux 7.x</b>.

- Profile Version: `3.6.0`
- [RedHat Enterprise Linux 7 Security Technical Implementation Guide v3r6](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_7_V3R6_STIG.zip)

This profile was developed to reduce the time it takes to perform a security checks based upon the STIG Guidance from the Defense Information Systems Agency (DISA) in partnership between the DISA Services Directorate (SD) and the DISA Risk Management Execute (RME) offices.

The profile results will provide information needed to support your Authority to Operate (ATO) decision for the applicable technology.

The <b>RHEL7 STIG Profile</b> uses the [InSpec](https://github.com/inspec/inspec) open-source compliance validation language to support automation of the required compliance, security and policy testing required for your Assessment and Authorization (A&A) and Authority to Operation (ATO) decisions, and your Continuous Authority to Operate (cATO) processes.

## RedHat 7.x Enterprise Linux Security Technical Implementation Guide (RHEL7 STIG)

The <b>RHEL7 STIG</b> (<https://public.cyber.mil/stigs/>) by the United States Defense Information Systems Agency (DISA) offers a comprehensive compliance guide for the configuration and operation of various technologies.

DISA has created and maintains a set of Security Technical Implementation Guides' for applications, computer systems or networks connected to the DoD. These guidelines are the primary security standards used by the DoD agencies. In addition to defining security guidelines, the STIGs also stipulate how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

The requirements associated with the <b>RHEL7 STIG</b> are derived from the [Security Requirements Guides](https://csrc.nist.gov/glossary/term/security_requirements_guide) and align to the [National Institute of Standards and Technology](https://www.nist.gov/) (NIST) [Special Publication (SP) 800-53](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/800-53) Security Controls, [DoD Control Correlation Identifier](https://public.cyber.mil/stigs/cci/) and related standards.

The RHEL7.x STIG profile checks were developed to provide technical implementation validation to the defined DoD requirements, the guidance can provide insight for any organizations wishing to enhance their security posture and can be tailored easily for use in your organization.

### Source Guidance

- [RedHat Enterprise Linux 7 Security Technical Implementation Guide v3r6](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_7_V3R6_STIG.zip)

### Update History

| Guidance Version | Guidance Location                                                              | Profile Version | Profile Release Date | STIG EOL | Profile EOL |
| ---------------- | ------------------------------------------------------------------------------ | --------------- | -------------------- | -------- | ----------- |
| v3r6             | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_7_V3R6_STIG.zip> | 3.6.0           | FIXME                | N/A      | N/A         |
| v3r5             | <https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_7_V3R5_STIG.zip> | 1.0.0           | N/A                  | N/A      | N/A         |

## Getting Started

It is intended and recommended that InSpec and this profile be run from a **"runner"** host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target [ remotely over **ssh**].

**For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.**

The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment

### Profile Inputs (see `inspec.yml` file)

This profile uses InSpec Inputs to make the tests more flexible. You are able to provide inputs at runtime either via the cli or via YAML files to help the profile work best in your deployment.

**Do not change the inputs in the inspec.yml file**

To tailor the tested values for your deployment or organizationally defined values, you may update the inputs:

1. Via the cli with the `--input` flag
2. Pass them in a YAML file with the `--input-file` flag.

More information about InSpec inputs can be found in the [InSpec Inputs Documentation](https://docs.chef.io/inspec/inputs/).

#### See the `inspec.yml` file for full list of avalible inputs

Example Inputs

```yaml
inputs:
  - name: disable_slow_controls
    description: Controls that are known to consistently have long run times can be disabled with this attribute
    type: Boolean
    value: false

  # V-204504
  - name: monitor_kernel_log
    description: Set this to false if your system availability concern is not documented or there is no monitoring of the kernel log
    type: Boolean
    value: true

  # V-204392
  - name: rpm_verify_perms_except
    description: List of system files that should be allowed to change from an rpm verify point of view
    type: Array
    value:
      - "/etc/issue"

  # V-214799
  - name: rpm_verify_integrity_except
    description: List of system files that should be allowed to change from an rpm verify point of view
    type: Array
    value: []
```

## (connected) Running the Profile Directly

```
inspec exec https://gitlab.dsolab.io/scv-content/inspec/operating-systems/redhat-enterprise-linux-7-stig-baseline.git --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>
```

### Different Run Options

[Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## (disconnected) Running the profile from a local archive copy

If your runner is not always expected to have direct access to the profile's hosted location, use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the **"runner"** host uses this profile overlay for the first time, follow these steps:

```
mkdir profiles
cd profiles
git clone https://gitlab.dsolab.io/scv-content/inspec/operating-systems/redhat-enterprise-linux-7-stig-baseline.git
inspec archive redhat-enterprise-linux-7-stig-baseline
<sneakerNet your archive>
inspec exec <name of generated archive> --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

1. Delete and recreate your archive as shown above
2. Update your archive with the following steps

```
cd redhat-enterprise-linux-7-stig-baseline
git pull
cd ..
inspec archive redhat-enterprise-linux-7-stig-baseline
```

## Using Heimdall-Lite for Viewing the JSON Results

The JSON results output file can be loaded into **[heimdall-lite](https://heimdall-lite.mitre.org/)** for a user-interactive, graphical view of the profile scan results.

It can also **_export your results into a DISA Checklist (CKL) file_** for easily upload into eMass.

The JSON results file may also be loaded into a **[full heimdall server](https://github.com/mitre/heimdall)**, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Feedback and Support

For questions or comments regarding the validation profile, please contact the DISA Service Directorate DevSecOps Help Desk: <disa.meade.sd.mbx.devsecops-mailbox@mail.mil>

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)

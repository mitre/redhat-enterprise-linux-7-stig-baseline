# red-hat-enterprise-linux-7-stig-baseline

InSpec profile to validate the secure configuration of Red Hat Enterprise Linux 7 against [DISA's](https://public.cyber.mil/stigs/downloads/) Red Hat Enterprise Linux 7 STIG Version 3 Release 10.

## Getting Started  
It is intended and recommended that InSpec and this profile be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __ssh__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment

The following inputs may be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```yaml
# Used by InSpec checks SV-204392, SV-204478, SV-214799
# InSpec Tests that are known to consistently have long run times can be disabled with this attribute
# Acceptable values: false, true
# (default: false)
disable_slow_controls: 

# Set this to false if your system availability concern is not documented or there is no monitoring of the kernel log
# (default: true)
monitor_kernel_log: 

# Used by InSpec check SV-204392
# list of system files that should be allowed to change from an rpm verify point of view
rpm_verify_perms_except: []

# Used by InSpec check SV-214799
# list of system files that should be allowed to change from an rpm verify point of view
rpm_verify_integrity_except: []

# Set to 'true' if the login banner message should be enabled
# (default: true)
banner_message_enabled: 

# Used by InSpec check SV-204575 (default: false)
# Do NOT set to 'true' UNLESS the server is documented as being used as a log aggregation server. 
log_aggregation_server: 

# Used by InSpec check SV-204624 (default: false)
# Do NOT set to 'true' UNLESS use of X Windows System is documented and approved. 
x11_enabled: 

# Accounts of known managed users (Array)
user_accounts: []

# System accounts that support approved system activities. (Array) (defaults shown below)
known_system_accounts: []

# User to use to check dconf settings. Nil means to use whatever user is running inspec currently.
dconf_user: ''

# Banner message text for graphical user interface logins.
banner_message_text_gui: ''

# Banner message text for limited-resource graphical user interface logins.
banner_message_text_gui_limited: ''

# Banner message text for command line interface logins.
banner_message_text_cli: ''

# Banner message text for resource-limited command line interface logins.
banner_message_text_cli_limited: ''

# Banner message text for remote access logins.
banner_message_text_ral: ''

# Banner message text for resource-limited remote access logins.
banner_message_text_ral_limited: ''

# The scereensaver lock-delay must be less than or equal to the specified value
lock_delay: 5

# Minimum number of characters that must be different from previous password
difok: 8

# Number of reuse generations
min_reuse_generations: 5

# Number of days
days_of_inactivity: 0

# number of unsuccessful attempts
unsuccessful_attempts: 3

# Interval of time in which the consecutive failed logon attempts must occur in order for the account to be locked out (time in seconds)
fail_interval: 900

# Minimum amount of time account must be locked out after failed logins. This attribute should never be set greater than 604800 (time in seconds).
lockout_time: 604800

# Name of tool
file_integrity_tool: ''

# Interval to run the file integrity tool (monthly, weekly, or daily).
file_integrity_interval: ''

# Used by InSpec checks SV-204498 SV-204499 SV-204500 (default: "/etc/aide.conf")
# Path to the aide.conf file
aide_conf_path:

# System activity timeout (time in seconds).
system_activity_timeout: 600

# Client alive interval (time in seconds).
client_alive_interval: 600

# SV-204441, SV-204631, SV-204633
# (enabled or disabled)
smart_card_status: "enabled"

# SV-204489, SV-204574
# The path to the logging package
log_pkg_path: "/etc/rsyslog.conf"

# SV-204467, SV-204468, SV-204469, SV-204470, SV-204471, SV-204472, SV-204473
# SV-204474, SV-204475, SV-204476, SV-204477, SV-204478, SV-204493
<<<<<<< HEAD
# Users exempt from home directory-based controls in array
# format
=======
# Users exempt from home directory-based controls in array format
>>>>>>> 790232a0e1364fbeef798a5f1c3d39c44a651f50
exempt_home_users: []

# SV-244557
# main grub boot config file
grub_main_cfg: ""

# Main grub boot config file
grub_uefi_main_cfg: ''

# grub boot config files
grub_user_boot_files: []

# SV-204444
# system accounts that support approved system activities
admin_logins: []

# The list of packages needed for MFA on RHEL
mfa_pkg_list: []

# SV-204397
# should dconf have smart card authentication (e.g., true or false <- no quotes!)
multifactor_enabled: true

# These shells do not allow a user to login
non_interactive_shells: []

# Randomize virtual address space kernel parameter
randomize_va_space: 2

# File systems that don't correspond to removable media
non_removable_media_fs: []

# SV-204629
# approved configured tunnels prepended with word 'conn'
# Example: ['conn myTunnel']
approved_tunnels: []

# SV-204479
# Is the target expected to be a virtual machine
virtual_machine: false

# maximum number of password retries
max_retry: 3

# Services that firewalld should be configured to allow.
firewalld_services: []

# Hosts that firewalld should be configured to allow.
firewalld_hosts_allow: []

# Hosts that firewalld should be configured to deny.
firewalld_hosts_deny: []

# Ports that firewalld should be configured to allow.
firewalld_ports_allow: []

# Ports that firewalld should be configured to deny.
firewalld_ports_deny: {}

# Allow rules from etc/hosts.allow.
tcpwrappers_allow: {}

# Deny rules from etc/hosts.deny.
tcpwrappers_deny: {}

# Iptable rules that should exist.
iptables_rules: []

# Services that firewalld should be configured to deny.
firewalld_services_deny: {}

# Zones that should be present on the system.
firewalld_zones: []

# The maxium value that can be used for maxlogins.
maxlogins_limit: 10

# Whether an antivirus solution, other than nails, is in use.
custom_antivirus: false

# Description of custom antivirus solution, when in use.
custom_antivirus_description: ''

# It is reasonable and advisable to skip checksum on frequently changing files
aide_exclude_patterns: []

# Required PAM rules
required_rules: []

# Alternate PAM rules
alternate_rules: []

# An alternate method is used for logs than rsyslog
alternate_logs: false

# is GSSAPI authentication approved
gssapi_approved: true

# Set flag to true if the target system is disconnected
disconnected_system: false
```
## Long Running Controls

There are a few long running controls that take anywhere from 3 minutes to 10 minutes or more to run. In an ongoing or CI/CD pipelne this may not be ideal. We have supplied an 
input (mentioned above in the user-defined inputs) in the profile to allow you to 'skip' these controls to account for these situations.

The input `disable_slow_controls (bool: false)` can be set to `true` or `false` as needed in a <name_of_your_input_file>.yml file.

## Running This Profile Directly from Github

Against a remote target using ssh with escalated privileges (i.e., InSpec installed on a separate runner host)
```bash
# How to run 
inspec exec https://github.com/mitre/redhat-enterprise-linux-7-stig-baseline/archive/main.tar.gz -t ssh://TARGET_USERNAME:TARGET_PASSWORD@TARGET_IP:TARGET_PORT --sudo --sudo-password=<SUDO_PASSWORD_IF_REQUIRED> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

Against a remote target using a pem key with escalated privileges (i.e., InSpec installed on a separate runner host)
```bash
# How to run 
inspec exec https://github.com/mitre/redhat-enterprise-linux-7-stig-baseline/archive/main.tar.gz -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>  
```

Against a local Red Hat host with escalated privileges (i.e., InSpec installed on the target)
```bash
# How to run
sudo inspec exec https://github.com/mitre/redhat-enterprise-linux-7-stig-baseline/archive/main.tar.gz --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```
### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy
If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this profile and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.) 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/redhat-enterprise-linux-7-stig-baseline.git
inspec archive redhat-enterprise-linux-7-stig-baseline
sudo inspec exec <name of generated archive> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

For every successive run, follow these steps to always have the latest version of this baseline and dependent profiles:

```
cd redhat-enterprise-linux-7-stig-baseline
git pull
cd ..
inspec archive redhat-enterprise-linux-7-stig-baseline --overwrite
sudo inspec exec <name of generated archive> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

## Using Heimdall for Viewing the JSON Results

![Heimdall Lite 2.0 Demo GIF](https://github.com/mitre/heimdall2/blob/master/apps/frontend/public/heimdall-lite-2.0-demo-5fps.gif)

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Sam Cornwell
* Danny Haynes
* Trevor Vaughan
* Aaron Lippold
* Kyle Fagan
* LJ Kimmel
* KC Linden
* Rony Xavier
* Mohamed El-Sharkawi
* Will Dower
* Emily Rodriguez
* Henry Xiao

## Special Thanks
* The SIMP Project Team
* Eugene Aronne
* Shivani Karikar

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/redhat-enterprise-linux-7-stig-baseline/issues/new).


# Appendix - (For Developers Interested in Running Hardening Tests):

This repository uses [KitchenCI](http://kitchen.ci) framework to run tests on the
various profiles. Please see the documentation below on how to use the framework. 

# Testing with Kitchen

## Dependencies

- Ruby 2.3.0 or later
- [Virtualbox](https://www.virtualbox.org)
- [Vagrant](https://www.vagrantup.com)

#### _Notes to Windows Users_

1. An installation of ChefDK may generate conflicts when combined with the
   installed kitchen gems. **Recommend NOT installing ChefDK before testing
   with this repo.**

2. If you run into errors when running `bundle install`, use the following
   commands to install gems:

- `gem install kitchen-ansible`
- `gem install kitchen-vagrant`

3. If the tests are not found when running `kitchen verify`, open
   `.kitchen.yml` and consult `inspec_tests` under the `suites` section.

4) You may also experience an error when running `kitchen converge` where a
   folder is unable to be created due to the length of the path. In this case,
   you may need to edit a registry key as explained
   [here](https://www.howtogeek.com/266621/how-to-make-windows-10-accept-file-paths-over-260-characters/).

## Setting up your box

1. Clone the repo via `git clone https://github.com/mitre/redhat-enterprise-linux-7-stig-baseline/main.git`
2. cd to `redhat-enterprise-linux-7-stig-baseline`
3. Run `bundle install`
4. Run `kitchen list` - you should see the following choice:
   - `vanilla-rhel-7`
   - `hardened-rhel-7`
5. Run `kitchen converge`
6. Run `kitchen list` - your should see your host with status "converged"
7. RUn `kitchen verify` to execute inspec profiles against target

# Hardening Development

Included in this repository are testing scripts which allow you to run the profile using Vagrant or EC2 VMs. You can choose which environment your VMs are run in by passing the appropriate test-kitchen `yml` file to your `KITCHEN_LOCAL_YAML` environment variable. All of the commands below use the `kitchen.vagrant.yml` file as an example, however a `kitchen.ec2.yaml` is also available in the repository and can be substituted below to run the tests in EC2.

- Making Changes and Testing

  - run `CHEF_LICENSE=accept KITCHEN_LOCAL_YAML=kitchen.vagrant.yml kitchen converge (machine name)` - runs any changes to your hardening scripts
  - run `kitchen verify (machine name)` - runs the inspec tests

- Starting Clean:
  - run `CHEF_LICENSE=accept KITCHEN_LOCAL_YAML=kitchen.vagrant.yml kitchen destroy (machine name)` kitchen will drop your box and you can start clean
- Going through the entire process ( create, build, configure, verify, destroy )
  - run `CHEF_LICENSE=accept KITCHEN_LOCAL_YAML=kitchen.vagrant.yml kitchen test (machine name)` or to test all defined machines `kitchen test`
- Just running the validation scripts
  - run `CHEF_LICENSE=accept KITCHEN_LOCAL_YAML=kitchen.vagrant.yml kitchen verify (machine name)`
- Just run one or more controls in the validation
  - edit the kitchen.yml file in the `controls:` section add the `control id(s)` to the list
- Skipping one or more tags in the hardening content 
  - run `CHEF_LICENSE=accept KITCHEN_LOCAL_YAML=kitchen.vagrant.yml ANSIBLE_EXTRA_FLAGS='--skip-tags=(tags)' kitchen converge (machine name)` kitchen will skip the tasks in the hardening script specified with the tags. 

### NOTICE

© 2018-2022 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.

### NOTICE
DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx

# amazon-linux-2-stig-ready-baseline

InSpec profile to validate the secure configuration of Amazon Linux 2 against STIG-ready content.

## Getting Started  
It is intended and recommended that InSpec and this profile be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __ssh__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

### Sudo Password

The hardening configures the system to require a sudo password.  You should set the sudo password you want via an Environment Variable as `SUDO_PASSWD` to test-kitchen can set it correctly. 

The default is set to 'P@ssw0rd!' ***WHICH YOU NEED TO UPDATE***.

The GitHub Actions Set the sudo password they use via a shared secret.

## Tailoring to Your Environment

The following inputs may be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```yaml
# Used by InSpec checks AMZL-02-710010, AMZL-02-720730, AMZL-02-710020
# InSpec Tests that are known to consistently have long run times can be disabled with this attribute
# Acceptable values: false, true
# (default: false)
disable_slow_controls: 

# Set this to false if your system availability concern is not documented or there is no monitoring of the kernel log
# (default: true)
monitor_kernel_log: 

# Used by InSpec check AMZL-02-710010
# list of system files that should be allowed to change from an rpm verify point of view
rpm_verify_perms_except: []

# Used by InSpec check AMZL-02-710020
# list of system files that should be allowed to change from an rpm verify point of view
rpm_verify_integrity_except: []

# Set to 'true' if the login banner message should be enabled
# (default: true)
banner_message_enabled: 

# Used by InSpec check AMZL-02-731010 (default: false)
# Do NOT set to 'true' UNLESS the server is documented as being used as a log aggregation server. 
log_aggregation_server: 

# Used by InSpec check AMZL-02-740730 (default: false)
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

# Used by InSpec checks AMZL-02-721600 AMZL-02-721610 AMZL-02-721620 (default: "/etc/aide.conf")
# Path to the aide.conf file
aide_conf_path:

# System activity timeout (time in seconds).
system_activity_timeout: 600

# Client alive interval (time in seconds).
client_alive_interval: 600

# AMZL-02-710500, AMZL-02-741001, AMZL-02-741003
# (enabled or disabled)
smart_card_status: "enabled"

# AMZL-02-721100, AMZL-02-731000
# The path to the logging package
log_pkg_path: "/etc/rsyslog.conf"

# AMZL-02-720620, AMZL-02-720630, AMZL-02-720640, AMZL-02-720650, AMZL-02-720660, AMZL-02-720670, AMZL-02-720680
# AMZL-02-720690, AMZL-02-720700, AMZL-02-720710, AMZL-02-720720, AMZL-02-720730, AMZL-02-721310
# Users exempt from home directory-based controls in array format
exempt_home_users: []

# AMZL-02-710483
# main grub boot config file
grub_main_cfg: ""

# Main grub boot config file
grub_uefi_main_cfg: ''

# grub boot config files
grub_user_boot_files: []

# AMZL-02-720020
# system accounts that support approved system activities
admin_logins: []

# The list of packages needed for MFA on AMZN
mfa_pkg_list: []

# AMZL-02-710061
# should dconf have smart card authentication (e.g., true or false <- no quotes!)
multifactor_enabled: true

# These shells do not allow a user to login
non_interactive_shells: []

# Randomize virtual address space kernel parameter
randomize_va_space: 2

# File systems that don't correspond to removable media
non_removable_media_fs: []

# AMZL-02-740820
# approved configured tunnels prepended with word 'conn'
# Example: ['conn myTunnel']
approved_tunnels: []

# AMZL-02-720900
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
inspec exec https://github.com/mitre/amazon-linux-2-stig-ready-baseline/archive/main.tar.gz -t ssh://TARGET_USERNAME:TARGET_PASSWORD@TARGET_IP:TARGET_PORT --sudo --sudo-password=<SUDO_PASSWORD_IF_REQUIRED> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

Against a remote target using a pem key with escalated privileges (i.e., InSpec installed on a separate runner host)
```bash
# How to run 
inspec exec https://github.com/mitre/amazon-linux-2-stig-ready-baseline/archive/main.tar.gz -t ssh://TARGET_USERNAME@TARGET_IP:TARGET_PORT --sudo -i <your_PEM_KEY> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>  
```

Against a local Red Hat host with escalated privileges (i.e., InSpec installed on the target)
```bash
# How to run
sudo inspec exec https://github.com/mitre/amazon-linux-2-stig-ready-baseline/archive/main.tar.gz --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```
### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy
If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this profile and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.) 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/amazon-linux-2-stig-ready-baseline.git
inspec archive amazon-linux-2-stig-ready-baseline
sudo inspec exec <name of generated archive> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

For every successive run, follow these steps to always have the latest version of this baseline and dependent profiles:

```
cd amazon-linux-2-stig-ready-baseline
git pull
cd ..
inspec archive amazon-linux-2-stig-ready-baseline --overwrite
sudo inspec exec <name of generated archive> --input-file <path_to_your_input_file/name_of_your_input_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

## Using Heimdall for Viewing the JSON Results

![Heimdall Lite 2.0 Demo GIF](https://github.com/mitre/heimdall2/blob/master/apps/frontend/public/heimdall-lite-2.0-demo-5fps.gif)

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Shivani Karikar
* Will Dower

## Special Thanks
* Eugene Aronne
* Emily Rodriguez
* Aaron Lippold

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/amazon-linux-2-stig-ready-baseline/issues/new).

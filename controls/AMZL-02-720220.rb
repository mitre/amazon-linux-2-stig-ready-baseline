control 'AMZL-02-720220' do
  title 'The Amazon Linux 2 operating system must enable the SELinux targeted policy.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure
    may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system
    responsible for enforcing the system security policy and supporting the isolation of code and data on which the
    protection is based. Security functionality includes, but is not limited to, establishing system accounts,
    configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting
    intrusion detection parameters.
    This requirement applies to operating systems performing security function verification/testing and/or systems and
    environments that require this functionality.'
  desc 'check', %q(Per OPORD 16-0080, the preferred endpoint security tool is Endpoint Security for Linux (ENSL) in
    conjunction with SELinux.
    Verify the operating system verifies correct operation of all security functions.
    Check if "SELinux" is active and is enforcing the targeted policy with the following command:
    # sestatus
    SELinux status: enabled
    SELinuxfs mount: /selinux
    SELinux root directory: /etc/selinux
    Loaded policy name: targeted
    Current mode: enforcing
    Mode from config file: enforcing
    Policy MLS status: enabled
    Policy deny_unknown status: allowed
    Max kernel policy version: 28
    If the "Loaded policy name" is not set to "targeted", this is a finding.
    Verify that the /etc/selinux/config file is configured to the "SELINUXTYPE" to "targeted":
    # grep -i "selinuxtype" /etc/selinux/config | grep -v '^#'
    SELINUXTYPE = targeted
    If no results are returned or "SELINUXTYPE" is not set to "targeted", this is a finding.)
  desc 'fix', 'Configure the operating system to verify correct operation of all security functions.
    Set the "SELinuxtype" to the "targeted" policy by modifying the "/etc/selinux/config" file to have the following
    line:
    SELINUXTYPE=targeted
    A reboot is required for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag stig_id: 'AMZL-02-720220'
  tag cci: ['CCI-002165', 'CCI-002696']
  tag nist: ['AC-3 (4)', 'SI-6 a']
  tag subsystems: ['selinux']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable - SELinux settings must be handled on host' do
      skip 'Control not applicable - SELinux settings must be handled on host'
    end
  else
    describe command('sestatus') do
      its('stdout') { should match(/^Loaded\spolicy\sname:\s+targeted\n?$/) }
    end
    describe parse_config_file('/etc/selinux/config') do
      its('SELINUXTYPE') { should eq 'targeted' }
    end
  end
end

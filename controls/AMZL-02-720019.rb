control 'AMZL-02-720019' do
  title 'The Amazon Linux 2 operating system must implement the Endpoint Security for Linux Threat
    Prevention tool.'
  desc "Adding endpoint security tools can provide the capability to automatically take actions in response to
    malicious behavior, which can provide additional agility in reacting to network threats. These tools also often
    include a reporting capability to provide network awareness of the system, which may not otherwise exist in an
    organization's systems management regime."
  desc 'check', 'Per OPORD 16-0080, the preferred endpoint security tool is McAfee Endpoint Security for Linux (ENSL)
    in conjunction with SELinux.
    Procedure:
    Check that the following package has been installed:
    # rpm -qa | grep -i mcafeetp
    If the "mcafeetp" package is not installed, this is a finding.
    Verify that the daemon is running:
    # ps -ef | grep -i mfetpd
    If the daemon is not running, this is a finding.'
  desc 'fix', 'Install and enable the latest McAfee ENSLTP package.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-720019'
  tag cci: ['CCI-001263', 'CCI-000366']
  tag nist: ['SI-4 (5)', 'CM-6 b']
  tag subsystems: ['endpoint_security']
  tag 'host'
  tag 'container'

  describe package('mcafeetp') do
    it { should be_installed }
  end
  describe service('mfetpd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

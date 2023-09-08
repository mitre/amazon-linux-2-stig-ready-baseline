control 'AMZL-02-740390' do
  title 'The Amazon Linux 2 operating system must be configured so that the SSH daemon is configured to
    only use the SSHv2 protocol.'
  desc 'SSHv1 is an insecure implementation of the SSH protocol and has many well-known vulnerability exploits.
    Exploits of the SSH daemon could provide immediate root access to the system.'
  desc 'check', 'Check that the SSH daemon is configured to only use the SSHv2 protocol with the following command:
    # grep -i protocol /etc/ssh/sshd_config
    Protocol 2
    #Protocol 1,2
    If any protocol line other than "Protocol 2" is uncommented, this is a finding.'
  desc 'fix', 'Remove all Protocol lines that reference version "1" in "/etc/ssh/sshd_config" (this file may be named
    differently or be in a different location if using a version of SSH that is provided by a third-party vendor). The
    "Protocol" line must be as follows:
    Protocol 2
    The SSH service must be restarted for changes to take effect.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag satisfies: ['SRG-OS-000074-GPOS-00042', 'SRG-OS-000480-GPOS-00227']
  tag stig_id: 'AMZL-02-740390'
  tag cci: ['CCI-000197', 'CCI-000366']
  tag nist: ['IA-5 (1) (c)', 'CM-6 b']
  tag subsystems: ['ssh']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized AMZN' do
      skip 'Control not applicable - SSH is not installed within containerized AMZN'
    end
  else
    impact 0.0
    describe "Amazon Linux 2 uses the more recent version of SSH whereby Protocol 2 is configured by default and cannot be downgraded to 1. Not Applicable." do
      skip 'Amazon Linux 2 uses the more recent version of SSH whereby Protocol 2 is configured by default and cannot be downgraded to 1. Not Applicable.'
    end
  end
end

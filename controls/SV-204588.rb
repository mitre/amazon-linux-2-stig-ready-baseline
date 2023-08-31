control 'AMZL-02-740330' do
  title 'The Amazon Linux 2 operating system must be configured so that the SSH daemon does not allow
    authentication using RSA rhosts authentication.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will
    require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', 'Verify the SSH daemon does not allow authentication using RSA rhosts authentication.
    To determine how the SSH daemon's "RhostsRSAAuthentication" option is set, run the following command:
    # grep RhostsRSAAuthentication /etc/ssh/sshd_config
    RhostsRSAAuthentication no
    If the value is returned as "yes", the returned line is commented out, or no output is returned, this is a finding.)'
  desc 'fix', 'Configure the SSH daemon to not allow authentication using RSA rhosts authentication.
    Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "no":
    RhostsRSAAuthentication no
    The SSH service must be restarted for changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-740330'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['ssh']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized AMZN' do
      skip 'Control not applicable - SSH is not installed within containerized AMZN'
    end
  else 
    impact 0.0
    describe "Amazon Linux 2 uses the more recent version of SSH whereby RhostsRSAAuthentication is disabled by default. Not Applicable." do
      skip 'Amazon Linux 2 uses the more recent version of SSH whereby RhostsRSAAuthentication is disabled by default. Not Applicable.'
    end
  end
end

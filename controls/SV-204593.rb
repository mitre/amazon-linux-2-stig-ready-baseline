control 'AMZL-02-740380' do
  title 'The Amazon Linux 2 operating system must be configured so that the SSH daemon does not allow
    authentication using known hosts authentication.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will
    require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(Verify the SSH daemon does not allow authentication using known hosts authentication.
    To determine how the SSH daemon's "IgnoreUserKnownHosts" option is set, run the following command:
    # grep -i IgnoreUserKnownHosts /etc/ssh/sshd_config
    IgnoreUserKnownHosts yes
    If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to not allow authentication using known hosts authentication.
    Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes":
    IgnoreUserKnownHosts yes
    The SSH service must be restarted for changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-740380'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['ssh']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  else
    describe sshd_config do
      its('IgnoreUserKnownHosts') { should cmp 'yes' }
    end
  end
end

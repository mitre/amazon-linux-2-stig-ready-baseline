control 'AMZL-02-710300' do
  title 'The Amazon Linux 2 operating system must be configured so that the SSH daemon does not allow
    authentication using an empty password.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will
    require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(To determine how the SSH daemon's "PermitEmptyPasswords" option is set, run the following command:
    # grep -i PermitEmptyPasswords /etc/ssh/sshd_config
    PermitEmptyPasswords no
    If no line, a commented line, or a line indicating the value "no" is returned, the required value is set.
    If the required value is not set, this is a finding.)
  desc 'fix', 'To explicitly disallow remote logon from accounts with empty passwords, add or correct the following
    line in "/etc/ssh/sshd_config":
    PermitEmptyPasswords no
    The SSH service must be restarted for changes to take effect.  Any accounts with empty passwords should be disabled
    immediately, and PAM configuration should prevent users from being able to assign themselves empty passwords.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000106-GPOS-00053'
  tag stig_id: 'AMZL-02-710300'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
  tag subsystems: ['ssh']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized AMZN' do
      skip 'Control not applicable - SSH is not installed within containerized AMZN'
    end
  else
    describe.one do
      describe sshd_config do
        its('PermitEmptyPasswords') { should eq 'no' }
      end
      describe sshd_config do
        its('PermitEmptyPasswords') { should be_nil }
      end
    end
  end
end

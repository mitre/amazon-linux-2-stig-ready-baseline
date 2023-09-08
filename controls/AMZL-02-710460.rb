control 'AMZL-02-710460' do
  title 'The Amazon Linux 2 operating system must not allow users to override SSH environment variables.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Verify the operating system does not allow users to override environment variables to the SSH
    daemon.
    Check for the value of the "PermitUserEnvironment" keyword with the following command:
    # grep -i permituserenvironment /etc/ssh/sshd_config
    PermitUserEnvironment no
    If the "PermitUserEnvironment" keyword is not set to "no", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to not allow users to override environment variables to the SSH daemon.
    Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for "PermitUserEnvironment" keyword and set the
    value to "no":
    PermitUserEnvironment no
    The SSH service must be restarted for changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag stig_id: 'AMZL-02-710460'
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
    describe sshd_config do
      its('PermitUserEnvironment') { should eq 'no' }
    end
  end
end

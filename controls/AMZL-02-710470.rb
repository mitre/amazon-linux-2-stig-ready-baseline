control 'AMZL-02-710470' do
  title 'The Amazon Linux 2 operating system must not allow a non-certificate trusted host SSH logon to
    the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Verify the operating system does not allow a non-certificate trusted host SSH logon to the system.
    Check for the value of the "HostbasedAuthentication" keyword with the following command:
    # grep -i hostbasedauthentication /etc/ssh/sshd_config
    HostbasedAuthentication no
    If the "HostbasedAuthentication" keyword is not set to "no", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to not allow a non-certificate trusted host SSH logon to the system.
    Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for "HostbasedAuthentication" keyword and set the
    value to "no":
    HostbasedAuthentication no
    The SSH service must be restarted for changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag stig_id: 'AMZL-02-710470'
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
      its('HostbasedAuthentication') { should eq 'no' }
    end
  end
end

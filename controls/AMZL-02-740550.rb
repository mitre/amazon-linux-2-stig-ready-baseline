control 'AMZL-02-740550' do
  title 'The Amazon Linux 2 operating system must not contain shosts.equiv files.'
  desc 'The shosts.equiv files are used to configure host-based authentication for the system via SSH. Host-based
    authentication is not sufficient for preventing unauthorized access to the system, as it does not require
    interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', 'Verify there are no "shosts.equiv" files on the system.
    Check the system for the existence of these files with the following command:
    # find / -name shosts.equiv
    If any "shosts.equiv" files are found on the system, this is a finding.'
  desc 'fix', 'Remove any found "shosts.equiv" files from the system.
    # rm /[path]/[to]/[file]/shosts.equiv'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-740550'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['ssh']
  tag 'host'
  tag 'container'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized AMZN' do
      skip 'Control not applicable - SSH is not installed within containerized AMZN'
    end
  else
    describe command('find / -xdev -xautofs -name shosts.equiv') do
      its('stdout.strip') { should be_empty }
    end
  end
end

control 'AMZL-02-740470' do
  title 'The Amazon Linux 2 operating system must be configured so that the SSH daemon does not allow
    compression or only allows compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression
    software could result in compromise of the system from an unauthenticated connection, potentially with root
    privileges.'
  desc 'check', 'Verify the SSH daemon performs compression after a user successfully authenticates.

    Check that the SSH daemon performs compression after a user successfully authenticates with the following command:

     # grep -i compression /etc/ssh/sshd_config
     Compression delayed

    If the "Compression" keyword is set to "yes", is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Uncomment the "Compression" keyword in "/etc/ssh/sshd_config" (this file may be named differently or
    be in a different location if using a version of SSH that is provided by a third-party vendor) on the system and set
    the value to "delayed" or "no":
    Compression no
    The SSH service must be restarted for changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-740470'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['ssh']
  tag 'host'

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end

  elsif os.release.to_f >= 7.4
    impact 0.0
    describe "The release is #{os.release}" do
      skip 'For RHEL 7.4 and above, this requirement is not applicable.'
    end

  else

    describe.one do
      describe sshd_config do
        its('Compression') { should cmp 'delayed' }
      end
      describe sshd_config do
        its('Compression') { should cmp 'no' }
      end
    end
  end
end

control 'AMZL-02-740410' do
  title 'The Amazon Linux 2 operating system must be configured so that the SSH public host key files have
    mode 0644 or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  desc 'check', %q(Verify the SSH public host key files have mode "0644" or less permissive.
    Note: SSH public key files may be found in other directories on the system depending on the installation.
    The following command will find all SSH public key files on the system:
    # find /etc/ssh -name '*.pub' -exec ls -lL {} \;
    -rw-r--r-- 1 root root 618 Nov 28 06:43 ssh_host_dsa_key.pub
    -rw-r--r-- 1 root root 347 Nov 28 06:43 ssh_host_key.pub
    -rw-r--r-- 1 root root 238 Nov 28 06:43 ssh_host_rsa_key.pub
    If any file has a mode more permissive than "0644", this is a finding.)
  desc 'fix', 'Note: SSH public key files may be found in other directories on the system depending on the
    installation.
    Change the mode of public host key files under "/etc/ssh" to "0644" with the following command:
    # chmod 0644 /etc/ssh/*.key.pub'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-740410'
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
    pub_files = command("find #{input('public_host_key_directories').join(' ')} -xdev -name '*.pub'").stdout.split("\n")
    if !pub_files.nil? and !pub_files.empty?
      pub_files.each do |pubfile|
        describe file(pubfile) do
          it { should_not be_more_permissive_than(input('public_host_key_file_mode')) }
        end
      end
    else
      describe 'No public host key files found.' do
        subject { pub_files.nil? or pub_files.empty? }
        it { should eq true }
      end
    end
  end
end

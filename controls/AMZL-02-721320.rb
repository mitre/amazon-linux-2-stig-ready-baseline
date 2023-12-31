control 'AMZL-02-721320' do
  title 'The Amazon Linux 2 operating system must use a separate file system for /var.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a
    file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system/partition has been created for "/var".
    Check that a file system/partition has been created for "/var" with the following command:
    # grep /var /etc/fstab
    UUID=c274f65f    /var                    ext4    noatime,nobarrier        1 2
    If a separate entry for "/var" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var" path onto a separate file system.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-721320'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['/var', 'file_system']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe etc_fstab.where { mount_point == '/var/log' } do
      it { should exist }
    end
  end
end

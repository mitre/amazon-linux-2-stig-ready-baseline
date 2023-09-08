control 'AMZL-02-721330' do
  title 'The Amazon Linux 2 operating system must use a separate file system for the system audit data
    path.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a
    file system becoming full or failing.'
  desc 'check', 'Determine if the operating system is configured to have the "/var/log/audit" path is on a separate
    file system.
    # grep /var/log/audit /etc/fstab
    If no result is returned, or the operating system is not configured to have "/var/log/audit" on a separate file
    system, this is a finding.
    Verify that "/var/log/audit" is mounted on a separate file system:
    # mount | grep "/var/log/audit"
    If no result is returned, or "/var/log/audit" is not on a separate file system, this is a finding.'
  desc 'fix', 'Migrate the system audit data path onto a separate file system.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-721330'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['file_system', 'audit']
  tag 'host'

  audit_data_path = command("dirname #{auditd_conf.log_file}").stdout.strip

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe etc_fstab.where { mount_point == audit_data_path } do
      it { should exist }
    end
  end
end

control 'AMZL-02-720640' do
  title 'The Amazon Linux 2 operating system must be configured so that all local interactive user home
    directories are owned by their respective users.'
  desc "If a local interactive user does not own their home directory, unauthorized users could access or modify the
    user's files, and the users may not be able to access their own files."
  desc 'check', %q(Verify the assigned home directory of all local interactive users on the system exists.
    Check the home directory assignment for all local interactive users on the system with the following command:
    # ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
    -rwxr-x--- 1 smithj users 18 Mar 5 17:06 /home/smithj
    If any home directories referenced in "/etc/passwd" are not owned by the interactive user, this is a finding.)
  desc 'fix', %q(Change the owner of a local interactive user's home directories to that owner. To change the owner of
    a local interactive user's home directory, use the following command:
    Note: The example will be for the user smithj, who has a home directory of "/home/smithj".
    # chown smithj /home/smithj)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-720640'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['home_dirs']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    exempt_home_users = input('exempt_home_users')
    non_interactive_shells = input('non_interactive_shells')

    ignore_shells = non_interactive_shells.join('|')

    uid_min = login_defs.read_params['UID_MIN'].to_i
    uid_min = 1000 if uid_min.nil?

    findings = Set[]
    users.where do
      !shell.match(ignore_shells) && (uid >= uid_min || uid == 0)
    end.entries.each do |user_info|
      next if exempt_home_users.include?(user_info.username.to_s)

      describe directory(user_info.home) do
        it { should exist }
        its('owner') { should eq user_info.username }
      end
    end
  end
end

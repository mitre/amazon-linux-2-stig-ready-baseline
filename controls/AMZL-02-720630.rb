control 'AMZL-02-720630' do
  title 'The Amazon Linux 2 operating system must be configured so that all local interactive user home
    directories have mode 0750 or less permissive.'
  desc 'Excessive permissions on local interactive user home directories may allow unauthorized access to user files
    by other users.'
  desc 'check', %q(Verify the assigned home directory of all local interactive users has a mode of "0750" or less
    permissive.
    Check the home directory assignment for all non-privileged users on the system with the following command:
    Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of
    interactive use may be obtained from a number of log files containing system logon information.
    # ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
    -rwxr-x--- 1 smithj users  18 Mar  5 17:06 /home/smithj
    If home directories referenced in "/etc/passwd" do not have a mode of "0750" or less permissive, this is a finding.)
  desc 'fix', %q(Change the mode of interactive user's home directories to "0750". To change the mode of a local
    interactive user's home directory, use the following command:
    Note: The example will be for the user "smithj".
    # chmod 0750 /home/smithj)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-720630'
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

      findings += command("find #{user_info.home} -maxdepth 0 -perm -#{input('home_dir_mode')}").stdout.split("\n")
    end
    describe 'Home directories with excessive permissions' do
      subject { findings.to_a }
      it { should be_empty }
    end
  end
end

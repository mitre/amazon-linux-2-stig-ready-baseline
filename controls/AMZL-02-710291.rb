control 'AMZL-02-710291' do
  title 'The Amazon Linux 2 operating system must not have accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', %q(Check the "/etc/shadow" file for blank passwords with the following command:

$ sudo awk -F: '!$2 {print $1}' /etc/shadow

If the command returns any results, this is a finding.)
  desc 'fix', 'Configure all accounts on the system to have a password or lock the account with the following commands:

Perform a password reset:
$ sudo passwd [username]
Lock an account:
$ sudo passwd -l [username]'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag satisfies: nil
  tag stig_id: 'AMZL-02-710291'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['password', '/etc/shadow']
  tag 'host'
  tag 'container'

  empty_pw_users = shadow.where { password == '' }.users

  describe 'Passwords in /etc/shadow' do
    it 'should not be empty' do
      message = "Users with empty passwords: #{empty_pw_users.join(', ')}"
      expect(empty_pw_users).to be_empty, message
    end
  end
end

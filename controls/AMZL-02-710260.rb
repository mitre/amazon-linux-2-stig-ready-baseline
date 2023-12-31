control 'AMZL-02-710260' do
  title 'The Amazon Linux 2 operating system must be configured so that existing passwords are restricted
    to a 60-day maximum lifetime.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed
    periodically. If the operating system does not limit the lifetime of passwords and force users to change their
    passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', %q(Check whether the maximum time period for existing passwords is restricted to 60 days.
    # awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow
    If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure non-compliant accounts to enforce a 60-day maximum password lifetime restriction.
    # chage -M 60 [user]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag stig_id: 'AMZL-02-710260'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
  tag subsystems: ['password', '/etc/shadow', 'tty']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    shadow.users.each do |user|
      # filtering on non-system accounts (uid >= 1000)
      next unless user(user).uid >= 1000

      describe shadow.users(user) do
        its('max_days.first') { should cmp input('max_password_lifetime') }
      end
    end
  end
end

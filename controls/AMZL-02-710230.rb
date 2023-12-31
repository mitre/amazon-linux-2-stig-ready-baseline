control 'AMZL-02-710230' do
  title 'The Amazon Linux 2 operating system must be configured so that passwords for new users are
    restricted to a 24 hours/1 day minimum lifetime.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password
    reuse or history enforcement requirement. If users are allowed to immediately and continually change their password,
    the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding
    password reuse."
  desc 'check', 'Verify the operating system enforces 24 hours/1 day as the minimum password lifetime for new user
    accounts.
    Check for the value of "PASS_MIN_DAYS" in "/etc/login.defs" with the following command:
    # grep -i pass_min_days /etc/login.defs
    PASS_MIN_DAYS     1
    If the "PASS_MIN_DAYS" parameter value is not "1" or greater, or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce 24 hours/1 day as the minimum password lifetime.
    Add the following line in "/etc/login.defs" (or modify the line to have the required value):
    PASS_MIN_DAYS     1'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag stig_id: 'AMZL-02-710230'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
  tag subsystems: ['login_defs', 'password']

  describe login_defs do
    its('PASS_MIN_DAYS') { should cmp >= 1 }
    its('PASS_MIN_DAYS') { should_not be_nil }
  end
end

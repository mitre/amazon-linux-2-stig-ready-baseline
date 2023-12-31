control 'AMZL-02-710481' do
  title 'The Amazon Linux 2 operating system must require authentication upon booting into single-user and
    maintenance modes.'
  desc 'If the system does not require valid root authentication before it boots into single-user or maintenance
    mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system.'
  desc 'check', 'Verify the operating system must require authentication upon booting into single-user and
    maintenance modes.
    Check that the operating system requires authentication upon booting into single-user mode with the following
    command:
    # grep -i execstart /usr/lib/systemd/system/rescue.service | grep -i sulogin
    ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"
    If "ExecStart" does not have "/usr/sbin/sulogin" as an option, this is a finding.'
  desc 'fix', 'Configure the operating system to require authentication upon booting into single-user and maintenance
    modes.
    Add or modify the "ExecStart" line in "/usr/lib/systemd/system/rescue.service" to include "/usr/sbin/sulogin":
    ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag stig_id: 'AMZL-02-710481'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag subsystems: ['root', 'sulogin']
  tag 'host'
  tag 'container'

  describe command('grep -i execstart /usr/lib/systemd/system/rescue.service') do
    its('stdout.strip') { should match %r{/usr/sbin/sulogin} }
  end
end

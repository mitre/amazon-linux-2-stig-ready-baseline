control 'AMZL-02-710350' do
  title 'The Amazon Linux 2 operating system must be configured so that users must re-authenticate for
    privilege escalation.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have
    authorization.
    When operating systems provide the capability to escalate a functional capability, it is critical the user
    reauthenticate.'
  desc 'check', 'Verify the operating system requires users to reauthenticate for privilege escalation.
    Check the configuration of the "/etc/sudoers" and "/etc/sudoers.d/*" files with the following command:
    # grep -i authenticate /etc/sudoers /etc/sudoers.d/*
    If any uncommented line is found with a "!authenticate" tag, this is a finding.'
  desc 'fix', 'Configure the operating system to require users to reauthenticate for privilege escalation.
    Check the configuration of the "/etc/sudoers" file with the following command:
    # visudo
    Remove any occurrences of "!authenticate" tags in the file.
    Check the configuration of the "/etc/sudoers.d/*" files with the following command:
    # grep -i authenticate /etc/sudoers /etc/sudoers.d/*
    Remove any occurrences of "!authenticate" tags in the file(s).'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag stig_id: 'AMZL-02-710350'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
  tag subsystems: ['sudo']
  tag 'host'

  if virtualization.system.eql?('docker') && !command('sudo').exist?
    impact 0.0
    describe 'Control not applicable within a container without sudo enabled' do
      skip 'Control not applicable within a container without sudo enabled'
    end
  else
    describe command('grep -ir authenticate /etc/sudoers /etc/sudoers.d/*') do
      its('stdout') { should_not match(/!authenticate/) }
    end
  end
end

control 'AMZL-02-710450' do
  title 'The Amazon Linux 2 operating system must not allow an unrestricted logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Verify the operating system does not allow an unrestricted logon to the system via a graphical user
    interface.
    Note: If the system does not have GNOME installed, this requirement is Not Applicable.
    Check for the value of the "TimedLoginEnable" parameter in "/etc/gdm/custom.conf" file with the following command:
    # grep -i timedloginenable /etc/gdm/custom.conf
    TimedLoginEnable=false
    If the value of "TimedLoginEnable" is not set to "false", this is a finding.'
  desc 'fix', 'Configure the operating system to not allow an unrestricted account to log on to the system via a
    graphical user interface.
    Note: If the system does not have GNOME installed, this requirement is Not Applicable.
    Add or edit the line for the "TimedLoginEnable" parameter in the [daemon] section of the "/etc/gdm/custom.conf" file
    to "false":
    [daemon]
    TimedLoginEnable=false'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag stig_id: 'AMZL-02-710450'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['gdm']
  tag 'host'

  custom_conf = '/etc/gdm/custom.conf'

  if package('gdm').installed?
    impact 0.7
    if (f = file(custom_conf)).exist?
      describe ini(custom_conf) do
        its('daemon.TimedLoginEnable') { cmp false }
      end
    else
      describe f do
        it { should exist }
      end
    end
  else
    impact 0.0
    describe 'The system does not have GDM installed' do
      skip 'The system does not have GDM installed, this requirement is Not Applicable.'
    end
  end
end

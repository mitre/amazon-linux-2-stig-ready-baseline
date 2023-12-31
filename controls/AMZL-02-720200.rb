control 'AMZL-02-720200' do
  title 'The Amazon Linux 2 operating system must remove all software components after updated versions
    have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have
    been installed may be exploited by adversaries. Some information technology products may remove older versions of
    software automatically from the information system.'
  desc 'check', 'Verify the operating system removes all software components after updated versions have been
    installed.
    Check if yum is configured to remove unneeded packages with the following command:
    # grep -i clean_requirements_on_remove /etc/yum.conf
    clean_requirements_on_remove=1
    If "clean_requirements_on_remove" is not set to "1", "True", or "yes", or is not set in "/etc/yum.conf", this is a
    finding.'
  desc 'fix', 'Configure the operating system to remove all software components after updated versions have been
    installed.
    Set the "clean_requirements_on_remove" option to "1" in the "/etc/yum.conf" file:
    clean_requirements_on_remove=1'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag stig_id: 'AMZL-02-720200'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
  tag subsystems: ['yum']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/yum.conf') do
    its('main.clean_requirements_on_remove') { should match(/1|True|yes/i) }
  end
end

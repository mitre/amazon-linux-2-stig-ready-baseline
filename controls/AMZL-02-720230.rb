control 'AMZL-02-720230' do
  title 'The Amazon Linux 2 operating system must be configured so that the x86 Ctrl-Alt-Delete key
    sequence is disabled on the command line.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If
    accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term
    loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of
    unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any
    action is taken.'
  desc 'check', 'Verify the operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.

Check that the ctrl-alt-del.target is masked and not active with the following command:

$ sudo systemctl status ctrl-alt-del.target

ctrl-alt-del.target
Loaded: masked (/dev/null; bad)
Active: inactive (dead)

If the ctrl-alt-del.target is not masked, this is a finding.

If the ctrl-alt-del.target is active, this is a finding.'
  desc 'fix', 'Configure the system to disable the Ctrl-Alt-Delete sequence for the command line with the following commands:

$ sudo systemctl disable ctrl-alt-del.target

$ sudo systemctl mask ctrl-alt-del.target'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag stig_id: 'AMZL-02-720230'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag subsystems: ['gui', 'general']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    service_load_state = systemd_service('ctrl-alt-del.target').params.LoadState
    service_active_state = systemd_service('ctrl-alt-del.target').params.ActiveState

    describe 'ctrl-alt-del.target' do
      it 'should be masked' do
        expect(service_load_state).to cmp('masked')
      end
    end

    describe 'ctrl-alt-del.target' do
      it 'should be inactive' do
        expect(service_active_state).to cmp('inactive')
      end
    end
  end
end

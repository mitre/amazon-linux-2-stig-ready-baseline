control 'AMZL-02-710482' do
  title 'Amazon Linux 2 operating systems with a Basic Input/Output System (BIOS)
    must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid authentication before it boots into single-user or maintenance mode,
    anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2
    is the default boot loader for Amazon Linux 2 and is designed to require a password to boot into single-user mode or make
    modifications to the boot menu.'
  desc 'check', 'For systems that use UEFI, this is Not Applicable.
    Check to see if an encrypted grub superusers password is set. On systems that use a BIOS, use the following command:
    $ sudo grep -iw grub2_password /boot/grub2/user.cfg
    GRUB2_PASSWORD=grub.pbkdf2.sha512.[password_hash]
    If the grub superusers password does not begin with "grub.pbkdf2.sha512", this is a finding.'
  desc 'fix', 'Configure the system to encrypt the boot password for the grub superusers account with the
    grub2-setpassword command, which creates/overwrites the /boot/grub2/user.cfg file.
    Generate an encrypted grub2 password for the grub superusers account with the following command:
    $ sudo grub2-setpassword
    Enter password:
    Confirm password:'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag stig_id: 'AMZL-02-710482'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag subsystems: ['boot', 'bios']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  elsif file('/sys/firmware/efi').exist?
    impact 0.0
    describe 'System running UEFI' do
      skip 'The System is running UEFI, this control is Not Applicable.'
    end
  else
    impact 0.7
    input('grub_user_boot_files').each do |grub_user_file|
      describe file(grub_user_file) do
        it { should exist }
      end

      describe parse_config_file(grub_user_file) do
        its('GRUB2_PASSWORD') { should include 'grub.pbkdf2.sha512' }
      end
    end
  end
end
